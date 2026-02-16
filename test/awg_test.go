package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

type awgKeypair struct {
	privateKey string
	publicKey  string
}

func generateAwgKeypair(t *testing.T) awgKeypair {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return awgKeypair{
		privateKey: base64.StdEncoding.EncodeToString(key.Bytes()),
		publicKey:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}
}

func TestAwgEndpointSelf(t *testing.T) {
	serverKP := generateAwgKeypair(t)
	clientKP := generateAwgKeypair(t)

	// Server instance: AWG endpoint listening on serverPort, direct outbound
	startInstance(t, option.Options{
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeAwg,
				Tag:  "awg-server",
				Options: &option.AwgEndpointOptions{
					PrivateKey: serverKP.privateKey,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.1/24")},
					ListenPort: serverPort,
					MTU:        1280,
					Peers: []option.AwgPeerOptions{
						{
							PublicKey:  clientKP.publicKey,
							AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.2/32")},
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
				Tag:  "direct",
			},
		},
		Route: &option.RouteOptions{
			Final: "direct",
		},
	})

	// Client instance: SOCKS inbound + AWG endpoint connecting to server
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeAwg,
				Tag:  "awg-client",
				Options: &option.AwgEndpointOptions{
					PrivateKey: clientKP.privateKey,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.2/24")},
					MTU:        1280,
					Peers: []option.AwgPeerOptions{
						{
							Address:    "127.0.0.1",
							Port:       serverPort,
							PublicKey:  serverKP.publicKey,
							AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0")},
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{"mixed-in"},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: "awg-client",
							},
						},
					},
				},
			},
		},
	})

	time.Sleep(3 * time.Second) // wait for AWG handshake
	testSuitWg(t, clientPort, testPort)
}

func TestAwgEndpointObfuscatedSelf(t *testing.T) {
	serverKP := generateAwgKeypair(t)
	clientKP := generateAwgKeypair(t)

	awgParams := struct {
		Jc   int
		Jmin int
		Jmax int
		S1   int
		S2   int
		H1   string
		H2   string
		H3   string
		H4   string
	}{
		Jc: 4, Jmin: 40, Jmax: 70,
		S1: 20, S2: 30,
		H1: "1234567890", H2: "987654321", H3: "1122334455", H4: "3344332211",
	}

	// Server instance: AWG endpoint with obfuscation
	startInstance(t, option.Options{
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeAwg,
				Tag:  "awg-server",
				Options: &option.AwgEndpointOptions{
					PrivateKey: serverKP.privateKey,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.1/24")},
					ListenPort: serverPort,
					MTU:        1280,
					Jc:         awgParams.Jc,
					Jmin:       awgParams.Jmin,
					Jmax:       awgParams.Jmax,
					S1:         awgParams.S1,
					S2:         awgParams.S2,
					H1:         awgParams.H1,
					H2:         awgParams.H2,
					H3:         awgParams.H3,
					H4:         awgParams.H4,
					Peers: []option.AwgPeerOptions{
						{
							PublicKey:  clientKP.publicKey,
							AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.2/32")},
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
				Tag:  "direct",
			},
		},
		Route: &option.RouteOptions{
			Final: "direct",
		},
	})

	// Client instance: AWG endpoint with matching obfuscation params
	startInstance(t, option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
		},
		Endpoints: []option.Endpoint{
			{
				Type: C.TypeAwg,
				Tag:  "awg-client",
				Options: &option.AwgEndpointOptions{
					PrivateKey: clientKP.privateKey,
					Address:    badoption.Listable[netip.Prefix]{netip.MustParsePrefix("10.0.0.2/24")},
					MTU:        1280,
					Jc:         awgParams.Jc,
					Jmin:       awgParams.Jmin,
					Jmax:       awgParams.Jmax,
					S1:         awgParams.S1,
					S2:         awgParams.S2,
					H1:         awgParams.H1,
					H2:         awgParams.H2,
					H3:         awgParams.H3,
					H4:         awgParams.H4,
					Peers: []option.AwgPeerOptions{
						{
							Address:    "127.0.0.1",
							Port:       serverPort,
							PublicKey:  serverKP.publicKey,
							AllowedIPs: badoption.Listable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0")},
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeDirect,
			},
		},
		Route: &option.RouteOptions{
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{
							Inbound: []string{"mixed-in"},
						},
						RuleAction: option.RuleAction{
							Action: C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{
								Outbound: "awg-client",
							},
						},
					},
				},
			},
		},
	})

	time.Sleep(3 * time.Second) // wait for AWG handshake
	testSuitWg(t, clientPort, testPort)
}
