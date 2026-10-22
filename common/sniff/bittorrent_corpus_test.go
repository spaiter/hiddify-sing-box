package sniff_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
)

// Corpus-driven tests for the BitTorrent sniffers, migrated from the
// standalone spaiter/BitTorrentBlocker project so the detection logic that
// actually runs in production is the logic under test. The library version was
// a separate NFQUEUE tool; this fork's sniffers are what the route rule
// {"action":"sniff","sniffer":"bittorrent"} invokes.
//
// The sniffer lists below are copied from route/rule/rule_action.go, where
// sniffer name "bittorrent" is expanded. Keep them in sync: if a sniffer is
// added there and not here, the corpus silently stops covering it.
//
// Provenance and licensing of every capture: testdata/pcap/NOTICE.md.

func btStreamSniffers() []sniff.StreamSniffer {
	return []sniff.StreamSniffer{
		sniff.BitTorrent,
		sniff.BitTorrentMessage,
		sniff.BitTorrentFAST,
		sniff.BitTorrentExtended,
		sniff.BitTorrentHTTP,
		sniff.BitTorrentSignature,
		sniff.BitTorrentMSE,
	}
}

func btPacketSniffers() []sniff.PacketSniffer {
	return []sniff.PacketSniffer{
		sniff.UTP,
		sniff.UDPTracker,
		sniff.BitTorrentDHTPacket,
		sniff.BitTorrentLSD,
		sniff.BitTorrentSignaturePacket,
	}
}

// ---------------------------------------------------------------- pcap reader

type capturedPacket struct {
	isUDP   bool
	payload []byte
	dest    M.Socksaddr
}

// readCapture parses a classic pcap or pcapng file into transport payloads.
//
// Written by hand rather than pulled in as a dependency: this fork is a VPN
// core and adding gopacket to the main module for a test would drag a large
// dependency tree into every build.
//
// It returns an error rather than calling t.Skip or t.Fatal, deliberately. The
// first version skipped, and because testing.T.Skip aborts the whole test, a
// single malformed capture in the corpus (fuzz-2021-10-13.pcap, which nDPI
// also documents as unreadable) silently cancelled the entire false-positive
// sweep. The test reported PASS while checking nothing.
func readCapture(path string) ([]capturedPacket, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var frames [][]byte
	switch {
	case len(data) > 4 && (data[0] == 0xD4 || data[0] == 0xA1):
		// Classic pcap. The bytes on disk are the magic as the capturing host
		// wrote it, so d4c3b2a1 means little-endian.
		little := data[0] == 0xD4
		get32 := func(b []byte) uint32 {
			if little {
				return binary.LittleEndian.Uint32(b)
			}
			return binary.BigEndian.Uint32(b)
		}
		for off := 24; off+16 <= len(data); {
			incl := int(get32(data[off+8 : off+12]))
			if incl <= 0 || incl > 262144 || off+16+incl > len(data) {
				break
			}
			frames = append(frames, data[off+16:off+16+incl])
			off += 16 + incl
		}
	case len(data) > 4 && binary.LittleEndian.Uint32(data[:4]) == 0x0A0D0D0A:
		// pcapng: only Enhanced Packet Blocks carry payloads.
		for off := 0; off+12 <= len(data); {
			blockType := binary.LittleEndian.Uint32(data[off : off+4])
			blockLen := int(binary.LittleEndian.Uint32(data[off+4 : off+8]))
			if blockLen < 12 || off+blockLen > len(data) {
				break
			}
			if blockType == 6 && off+28 <= len(data) {
				capLen := int(binary.LittleEndian.Uint32(data[off+20 : off+24]))
				if capLen > 0 && off+28+capLen <= len(data) {
					frames = append(frames, data[off+28:off+28+capLen])
				}
			}
			off += blockLen
		}
	default:
		return nil, fmt.Errorf("unrecognised capture format")
	}

	var out []capturedPacket
	for _, frame := range frames {
		pkt, ok := decodeFrame(frame)
		if ok {
			out = append(out, pkt)
		}
	}
	return out, nil
}

func decodeFrame(frame []byte) (capturedPacket, bool) {
	if len(frame) < 14 {
		return capturedPacket{}, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	rest := frame[14:]

	var (
		proto   byte
		dstAddr netip.Addr
		tr      []byte
	)
	switch etherType {
	case 0x0800:
		if len(rest) < 20 {
			return capturedPacket{}, false
		}
		proto = rest[9]
		dstAddr = netip.AddrFrom4([4]byte(rest[16:20]))
		ihl := int(rest[0]&0x0F) * 4
		if ihl < 20 || ihl > len(rest) {
			return capturedPacket{}, false
		}
		tr = rest[ihl:]
	case 0x86DD:
		if len(rest) < 40 {
			return capturedPacket{}, false
		}
		proto = rest[6]
		dstAddr = netip.AddrFrom16([16]byte(rest[24:40]))
		tr = rest[40:]
	default:
		return capturedPacket{}, false
	}

	switch proto {
	case 6:
		if len(tr) < 20 {
			return capturedPacket{}, false
		}
		dataOff := int(tr[12]>>4) * 4
		if dataOff < 20 || dataOff > len(tr) {
			return capturedPacket{}, false
		}
		payload := tr[dataOff:]
		if len(payload) == 0 {
			return capturedPacket{}, false
		}
		return capturedPacket{
			payload: payload,
			dest:    M.SocksaddrFrom(dstAddr, binary.BigEndian.Uint16(tr[2:4])),
		}, true
	case 17:
		if len(tr) < 8 {
			return capturedPacket{}, false
		}
		payload := tr[8:]
		if len(payload) == 0 {
			return capturedPacket{}, false
		}
		return capturedPacket{
			isUDP:   true,
			payload: payload,
			dest:    M.SocksaddrFrom(dstAddr, binary.BigEndian.Uint16(tr[2:4])),
		}, true
	}
	return capturedPacket{}, false
}

// ------------------------------------------------------------------- sniffing

// sniffOne runs the production sniffer set over a single payload and reports
// whether any of them claimed it as BitTorrent, plus which detector fired.
func sniffOne(pkt capturedPacket) (bool, string) {
	metadata := &adapter.InboundContext{Destination: pkt.dest}
	ctx := context.Background()

	if pkt.isUDP {
		for _, sniffer := range btPacketSniffers() {
			if sniffer(ctx, metadata, pkt.payload) == nil &&
				metadata.Protocol == C.ProtocolBitTorrent {
				return true, metadata.SniffDetector
			}
		}
		return false, ""
	}
	for _, sniffer := range btStreamSniffers() {
		if sniffer(ctx, metadata, bytes.NewReader(pkt.payload)) == nil &&
			metadata.Protocol == C.ProtocolBitTorrent {
			return true, metadata.SniffDetector
		}
	}
	return false, ""
}

func sniffCapture(path string, maxPackets int) (analysed, detected int, byDetector map[string]int, err error) {
	byDetector = make(map[string]int)
	packets, err := readCapture(path)
	if err != nil {
		return 0, 0, byDetector, err
	}
	for i, pkt := range packets {
		if maxPackets > 0 && i >= maxPackets {
			break
		}
		analysed++
		if ok, detector := sniffOne(pkt); ok {
			detected++
			byDetector[detector]++
		}
	}
	return analysed, detected, byDetector, nil
}

func corpusDir(t testing.TB, which string) string {
	t.Helper()
	dir := filepath.Join("testdata", "pcap", which)
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("corpus %s unavailable: %v", which, err)
	}
	return dir
}

// -------------------------------------------------------------- true positive

func TestBitTorrentCorpusTruePositive(t *testing.T) {
	t.Parallel()
	dir := corpusDir(t, "true-positive")

	// Thresholds are set below the measured rate with roughly 10-15 points of
	// headroom. A threshold equal to the observation turns harmless variation
	// into a red test; one far below it stops catching regressions.
	cases := []struct {
		file       string
		minRate    float64
		maxPackets int
		note       string
	}{
		{"own_lsd_bep14.pcap", 90.0, 0, "measured 100%, 2 packets so 90 forces both"},
		{"own_dht_bep5.pcap", 90.0, 0, "measured 100%"},
		{"own_pex_bep11.pcap", 90.0, 600, "measured 99.67%"},
		{"own_socks5_wrapped_synthetic.pcap", 90.0, 0, "measured 100%: SOCKS5 unwrapping works"},
		{"own_plaintext_bep6_bep10.pcap", 50.0, 400, "measured 62.00%"},
		{"own_utp_bep29.pcap", 45.0, 600, "measured 53.50%"},
		{"own_ipv6_peer.pcap", 55.0, 600, "measured 64.83%"},
		{"own_udp_tracker_bep15.pcap", 80.0, 0, "measured 90%; the one miss is the 16-byte connect response, see udpTrackerResponse"},
		{"bittorrent.pcap", 50.0, 200, "measured 54.50%"},
		{"bittorrent_utp.pcap", 80.0, 100, "measured 89.13%"},
		{"suricata-dht.pcap", 80.0, 50, "measured 100%"},
		{"zeek_tracker.pcap", 40.0, 100, "measured 50.00%"},
		{"bt_search.pcap", 80.0, 50, "measured 100%"},
		{"targusdataspeed_dht.pcap", 80.0, 50, "measured 100%, DHT on port 5200"},
		{"torrent-dht.pcap", 80.0, 100, "measured 100%"},
		{"bt-http.pcapng", 50.0, 50, "measured 66.67% here; the library measured 100% with a different detector set"},

		// Rates that are legitimately low, recorded so a future improvement is
		// visible rather than mistaken for a regression.
		{"mippo.pcap", 15.0, 200, "measured 17.65%, mostly tracker and setup traffic"},
		{"bittorrent_tcp_miss.pcapng", 5.0, 100, "measured 6.94%, handshake was not captured"},
		{"bt-dns.pcap", 0.0, 50, "DNS lookups carry no BitTorrent markers"},
		{"tls_torrent.pcapng", 0.0, 50, "TLS-wrapped: 0% is correct, not a defect"},
		{"ustc_bittorrent.pcap", 0.0, 500, "TLS-wrapped research corpus"},

		// See TestBitTorrentMSEIsInert for why these two are zero.
		{"own_mse_handshake.pcap", 0.0, 400, "MSE handshake, ours"},
		{"own_mid_transfer.pcap", 0.0, 1200, "steady-state MSE traffic, ours"},
		{"own_mse_many_flows.pcap", 5.0, 0, "measured 5.83%: exactly its plaintext flows, none of the 126 MSE ones"},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			analysed, detected, byDetector, err := sniffCapture(filepath.Join(dir, tc.file), tc.maxPackets)
			if err != nil {
				t.Fatalf("%s: %v", tc.file, err)
			}
			if analysed == 0 {
				t.Fatalf("%s: no payload-bearing packets parsed", tc.file)
			}
			rate := float64(detected) / float64(analysed) * 100

			var detectors []string
			for name, n := range byDetector {
				detectors = append(detectors, fmt.Sprintf("%s=%d", name, n))
			}
			sort.Strings(detectors)
			t.Logf("%s (%s): %d/%d = %.2f%% (min %.2f%%) [%s]",
				tc.file, tc.note, detected, analysed, rate, tc.minRate,
				strings.Join(detectors, " "))

			if rate < tc.minRate {
				t.Errorf("detection rate %.2f%% below required %.2f%%", rate, tc.minRate)
			}
		})
	}
}

// ------------------------------------------------------------- false positive

// TestBitTorrentCorpusFalsePositive is the reason the 650-capture corpus is
// worth its disk space: it is what makes a change to the sniffers safe to
// make. Any loosening that starts eating Kerberos, TLS or SSH shows up here
// instead of in production.
func TestBitTorrentCorpusFalsePositive(t *testing.T) {
	t.Parallel()
	dir := corpusDir(t, "false-positive")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	// Detections that are accepted, each with the reason it is not a bug to
	// fix. Anything not listed here fails the test.
	allowed := map[string]string{
		// Not a false positive at all: this capture really does carry
		// BitTorrent DHT on port 6881, so detecting it is correct. nDPI ships
		// it under a name about IPv6 caches, and the standalone
		// BitTorrentBlocker project documented the same 18 detections.
		"lru_ipv6_caches.pcapng": "capture genuinely contains BitTorrent DHT on port 6881",
	}

	var captures, clean, unparseable int
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".pcap") && !strings.HasSuffix(name, ".pcapng") {
			continue
		}
		captures++
		analysed, detected, byDetector, err := sniffCapture(filepath.Join(dir, name), 0)
		if err != nil {
			unparseable++
			continue
		}
		if analysed == 0 || detected == 0 {
			clean++
			continue
		}
		if reason, ok := allowed[name]; ok {
			t.Logf("%s: %d/%d detections, allowed: %s", name, detected, analysed, reason)
			continue
		}
		var detectors []string
		for d, n := range byDetector {
			detectors = append(detectors, fmt.Sprintf("%s=%d", d, n))
		}
		sort.Strings(detectors)
		t.Errorf("FALSE POSITIVE %s: %d of %d packets detected as BitTorrent [%s]",
			name, detected, analysed, strings.Join(detectors, " "))
	}
	t.Logf("%d captures seen, %d clean, %d unparseable", captures, clean, unparseable)
	if captures < 500 {
		t.Errorf("only %d captures seen; corpus looks truncated", captures)
	}
	// A corpus that suddenly stops parsing would otherwise read as success.
	if parsed := captures - unparseable; parsed < 500 {
		t.Errorf("only %d of %d captures actually parsed; the sweep is not "+
			"covering what it claims to", parsed, captures)
	}
}

// --------------------------------------------------------------------- MSE

// TestBitTorrentMSEIsInert pins the measured fact that BitTorrentMSE never
// fires, so that nobody "fixes" it by relaxing a threshold without reading
// why. The full measurement is in testdata/pcap/NOTICE.md; in short:
//
//   - Its VC scan looks for 8 plaintext zero bytes, but MSE sends the
//     Verification Constant encrypted. 0 of 126 real MSE flows contain it.
//   - Its entropy gate is unreachable anyway: >6.5 over a 96-byte window needs
//     92 of 96 bytes distinct, while random data yields about 80.
//   - Relaxing it does not help. Every gate that catches all 126 MSE flows
//     also flags 16-19 captures in the false-positive corpus, consistently
//     ethereum, kerberos, zabbix and telegram_videocall, because those open
//     with cryptographic random material too.
//
// If this test starts failing, MSE detection began working and the thresholds
// in TestBitTorrentCorpusTruePositive should be raised to match.
func TestBitTorrentMSEIsInert(t *testing.T) {
	t.Parallel()
	dir := corpusDir(t, "true-positive")

	ctx := context.Background()
	packets, err := readCapture(filepath.Join(dir, "own_mse_many_flows.pcap"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var flows, fired int
	for _, pkt := range packets {
		if pkt.isUDP || bytes.Contains(pkt.payload, []byte("BitTorrent protocol")) {
			continue
		}
		flows++
		metadata := &adapter.InboundContext{Destination: pkt.dest}
		if sniff.BitTorrentMSE(ctx, metadata, bytes.NewReader(pkt.payload)) == nil {
			fired++
		}
	}
	if flows == 0 {
		t.Fatal("no encrypted payloads found; fixture is wrong")
	}
	t.Logf("BitTorrentMSE fired on %d of %d encrypted payloads", fired, flows)
	if fired != 0 {
		t.Errorf("BitTorrentMSE fired %d times; it was measured as inert. "+
			"If this is a deliberate improvement, re-measure against the "+
			"false-positive corpus and update NOTICE.md and the thresholds",
			fired)
	}
}

// TestBitTorrentMessageRejectsShortBitfield is a regression test for the one
// false positive the corpus sweep found in production logic.
//
// These bytes are a real packet from testdata/pcap/false-positive/netflix.pcap:
// plain HTTP video delivery from port 80, one of 911 packets in that capture.
// They parse as msgLen=3, msgID=5, which the Bitfield branch used to accept on
// nothing more than "small length, fifth byte is 0x05" -- its own guards only
// covered msgLen 8..12 and msgLen > 40. In production that meant a dropped
// connection and a one-minute XDP ban on a CDN address.
//
// What rejects it now is the chain check: the bitfield ends at offset 7 and the
// following four bytes are 0x3b000000, a length of ~989 MB, so the stream does
// not continue as BitTorrent.
func TestBitTorrentMessageRejectsShortBitfield(t *testing.T) {
	t.Parallel()

	payload, err := hex.DecodeString(
		"000000030546063b0000000002e5a4080101010000000306")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	var metadata adapter.InboundContext
	if err := sniff.BitTorrentMessage(context.Background(), &metadata,
		bytes.NewReader(payload)); err == nil {
		t.Errorf("HTTP video payload accepted as a BitTorrent Bitfield message; "+
			"detector %q", metadata.SniffDetector)
	}

	// A genuine bitfield whose message fills the segment exactly must still be
	// accepted, so the fix is not simply refusing short bitfields.
	genuine := []byte{0x00, 0x00, 0x00, 0x03, 0x05, 0xF0, 0x0F}
	metadata = adapter.InboundContext{}
	if err := sniff.BitTorrentMessage(context.Background(), &metadata,
		bytes.NewReader(genuine)); err != nil {
		t.Errorf("a bitfield that exactly fills the segment was rejected: %v", err)
	}
}
