package masquewg

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/quic-go/masque-go"
	qgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/awg"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEWGOutboundOptions](registry, C.TypeMASQUEWG, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx        context.Context
	logger     log.ContextLogger
	options    option.MASQUEWGOutboundOptions
	serverName string
	serverAddr string
	template   *uritemplate.Template
	tlsConfig  *tls.Config
	bind       *masqueBind
	device     *awg.Device
	dnsRouter  adapter.DNSRouter

	mu      sync.Mutex
	started bool
	conn    *masque.Conn
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEWGOutboundOptions) (adapter.Outbound, error) {
	if options.Server == "" || options.ServerPort == 0 {
		return nil, E.New("masque-wg: server and server_port are required")
	}
	if options.PrivateKey == "" || options.PeerPublicKey == "" {
		return nil, E.New("masque-wg: private_key and peer_public_key are required")
	}
	if len(options.LocalAddress) == 0 {
		return nil, E.New("masque-wg: local_address is required")
	}
	path := options.Path
	if path == "" {
		path = defaultPath
	}
	serverName := ""
	insecure := false
	if options.TLS != nil {
		serverName = options.TLS.ServerName
		insecure = options.TLS.Insecure
	}
	if serverName == "" {
		serverName = options.Server
	}
	tmpl := uritemplate.MustNew(fmt.Sprintf("https://%s:%d%s?h={target_host}&p={target_port}",
		serverName, options.ServerPort, path))

	ipc, err := genIpc(options)
	if err != nil {
		return nil, err
	}
	mtu := options.MTU
	if mtu == 0 {
		mtu = 1280
	}
	bind := newMasqueBind()
	dev, err := awg.NewDevice(ctx, logger, nil, ipc, awg.DeviceOpts{
		Address: options.LocalAddress,
		MTU:     mtu,
		Context: ctx,
		Bind:    bind,
	})
	if err != nil {
		return nil, E.Cause(err, "masque-wg: create device")
	}

	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeMASQUEWG, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:        ctx,
		logger:     logger,
		options:    options,
		serverName: serverName,
		serverAddr: net.JoinHostPort(options.Server, fmt.Sprint(options.ServerPort)),
		template:   tmpl,
		tlsConfig: &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{http3.NextProtoH3},
			InsecureSkipVerify: insecure,
		},
		bind:      bind,
		device:    dev,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
	}, nil
}

func (o *Outbound) PostStart() error {
	tr := &masque.Transport{
		TLSClientConfig: o.tlsConfig,
		QUICConfig:      &qgo.Config{EnableDatagrams: true, InitialPacketSize: 1350},
		DialAddr: func(ctx context.Context, _ string, tlsConf *tls.Config, quicConf *qgo.Config) (*qgo.Conn, error) {
			return qgo.DialAddr(ctx, o.serverAddr, tlsConf, quicConf)
		},
	}
	// The server locks the CONNECT-UDP target to its WG port, so the requested
	// target here is only used to expand the URI template; any valid host:port works.
	req, err := masque.NewRequest(o.ctx, o.template, "127.0.0.1:10863")
	if err != nil {
		return E.Cause(err, "masque-wg: build request")
	}
	pconn, rsp, err := tr.Dial(req)
	if err != nil {
		return E.Cause(err, "masque-wg: establish CONNECT-UDP")
	}
	if pconn == nil {
		return E.New("masque-wg: dial returned nil conn")
	}
	if rsp != nil && rsp.StatusCode/100 != 2 {
		return E.New("masque-wg: proxy rejected CONNECT-UDP, status ", rsp.StatusCode)
	}
	o.bind.SetConn(pconn)
	if err := o.device.Start(adapter.StartStateStart); err != nil {
		return E.Cause(err, "masque-wg: start wireguard device")
	}
	o.mu.Lock()
	o.conn = pconn
	o.started = true
	o.mu.Unlock()
	o.logger.Info("masque-wg: tunnel up (WireGuard over MASQUE CONNECT-UDP to ", o.serverAddr, ")")
	return nil
}

func (o *Outbound) ready() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.started
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !o.ready() {
		return nil, E.New("masque-wg: not started")
	}
	// The embedded netstack cannot resolve names itself; resolve FQDNs via
	// sing-box's DNS router and dial by IP (like the awg endpoint). //H
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("masque-wg: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, o.device, network, destination, addrs)
	}
	return o.device.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !o.ready() {
		return nil, E.New("masque-wg: not started")
	}
	if destination.IsFqdn() {
		if o.dnsRouter == nil {
			return nil, E.New("masque-wg: cannot resolve ", destination.Fqdn, " (no DNS router)")
		}
		addrs, err := o.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		conn, _, err := N.ListenSerial(ctx, o.device, destination, addrs)
		return conn, err
	}
	return o.device.ListenPacket(ctx, destination)
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	dev := o.device
	conn := o.conn
	o.started = false
	o.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	if conn != nil {
		conn.Close()
	}
	return nil
}

// genIpc renders the WireGuard/AmneziaWG IPC config for the embedded device. The
// endpoint is a placeholder (the masqueBind ignores it — there is one peer, the
// server WG behind the proxy). AWG obfuscation params must match the server. //H
func genIpc(o option.MASQUEWGOutboundOptions) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(o.PrivateKey)
	if err != nil {
		return "", E.Cause(err, "decode private_key")
	}
	pub, err := base64.StdEncoding.DecodeString(o.PeerPublicKey)
	if err != nil {
		return "", E.Cause(err, "decode peer_public_key")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s", hex.EncodeToString(priv))
	a := o.Awg
	if a.Jc != 0 {
		fmt.Fprintf(&b, "\njc=%d", a.Jc)
	}
	if a.Jmin != 0 {
		fmt.Fprintf(&b, "\njmin=%d", a.Jmin)
	}
	if a.Jmax != 0 {
		fmt.Fprintf(&b, "\njmax=%d", a.Jmax)
	}
	if a.S1 != 0 {
		fmt.Fprintf(&b, "\ns1=%d", a.S1)
	}
	if a.S2 != 0 {
		fmt.Fprintf(&b, "\ns2=%d", a.S2)
	}
	if a.S3 != 0 {
		fmt.Fprintf(&b, "\ns3=%d", a.S3)
	}
	if a.S4 != 0 {
		fmt.Fprintf(&b, "\ns4=%d", a.S4)
	}
	for k, v := range map[string]string{"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
		"i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5} {
		if v != "" {
			fmt.Fprintf(&b, "\n%s=%s", k, v)
		}
	}
	fmt.Fprintf(&b, "\npublic_key=%s", hex.EncodeToString(pub))
	if o.PreSharedKey != "" {
		psk, err := base64.StdEncoding.DecodeString(o.PreSharedKey)
		if err != nil {
			return "", E.Cause(err, "decode pre_shared_key")
		}
		fmt.Fprintf(&b, "\npreshared_key=%s", hex.EncodeToString(psk))
	}
	// Placeholder endpoint (bind ignores it); WireGuard requires one to be set.
	b.WriteString("\nendpoint=127.0.0.1:1")
	ka := o.PersistentKeepaliveInterval
	if ka == 0 {
		ka = 25
	}
	fmt.Fprintf(&b, "\npersistent_keepalive_interval=%d", ka)
	b.WriteString("\nallowed_ip=0.0.0.0/0")
	b.WriteString("\nallowed_ip=::/0")
	return b.String(), nil
}
