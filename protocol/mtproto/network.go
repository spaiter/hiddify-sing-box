package mtproto

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/9seconds/mtg/v2/essentials"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// mtgNetwork implements github.com/9seconds/mtg/v2/mtglib.Network on top of a
// sing-box dialer, so that all upstream connections mtg makes to Telegram data
// centers go through sing-box routing/outbounds. //H
type mtgNetwork struct {
	ctx    context.Context
	dialer N.Dialer
}

func (n *mtgNetwork) Dial(network, address string) (essentials.Conn, error) {
	return n.DialContext(n.ctx, network, address)
}

func (n *mtgNetwork) DialContext(ctx context.Context, network, address string) (essentials.Conn, error) {
	conn, err := n.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
	if err != nil {
		return nil, err
	}
	return essentialsConn{Conn: conn}, nil
}

func (n *mtgNetwork) MakeHTTPClient(dialFunc func(ctx context.Context, network, address string) (essentials.Conn, error)) *http.Client {
	if dialFunc == nil {
		dialFunc = n.DialContext
	}
	return &http.Client{
		Timeout: time.Minute,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialFunc(ctx, network, address)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func (n *mtgNetwork) NativeDialer() *net.Dialer {
	return &net.Dialer{}
}
