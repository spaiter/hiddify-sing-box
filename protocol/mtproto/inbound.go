// Package mtproto integrates the github.com/9seconds/mtg Telegram MTProto proxy
// as a sing-box inbound. sing-box owns the TCP listener and hands each accepted
// connection to mtglib.Proxy.ServeConn; upstream connections to Telegram data
// centers are dialed through sing-box routing via mtgNetwork. //H
package mtproto

import (
	"context"
	"net"

	"github.com/9seconds/mtg/v2/antireplay"
	"github.com/9seconds/mtg/v2/events"
	"github.com/9seconds/mtg/v2/ipblocklist"
	"github.com/9seconds/mtg/v2/mtglib"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MTProtoInboundOptions](registry, C.TypeMTProto, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx      context.Context
	logger   log.ContextLogger
	listener *listener.Listener
	proxy    *mtglib.Proxy
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MTProtoInboundOptions) (adapter.Inbound, error) {
	secret, err := mtglib.ParseSecret(options.Secret)
	if err != nil {
		return nil, E.Cause(err, "parse mtproto secret")
	}

	// Route upstream connections to Telegram DCs through sing-box, reusing the
	// listener's routing/socket knobs (set `detour` to chain via an outbound).
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx,
		Options: option.DialerOptions{
			Detour:               options.Detour,
			BindInterface:        options.BindInterface,
			RoutingMark:          options.RoutingMark,
			ReuseAddr:            options.ReuseAddr,
			NetNs:                options.NetNs,
			TCPFastOpen:          options.TCPFastOpen,
			TCPMultiPath:         options.TCPMultiPath,
			DisableTCPKeepAlive:  options.DisableTCPKeepAlive,
			TCPKeepAlive:         options.TCPKeepAlive,
			TCPKeepAliveInterval: options.TCPKeepAliveInterval,
		},
		RemoteIsDomain: true,
	})
	if err != nil {
		return nil, err
	}

	proxy, err := mtglib.NewProxy(mtglib.ProxyOpts{
		Secret:          secret,
		Network:         &mtgNetwork{ctx: ctx, dialer: outboundDialer},
		AntiReplayCache: antireplay.NewStableBloomFilter(1024*1024, 0.001),
		IPBlocklist:     ipblocklist.NewNoop(),
		IPAllowlist:     newAllowAllList(),
		EventStream:     events.NewNoopStream(),
		Logger:          newMTGLogger(logger),
		Concurrency:     uint(options.Concurrency),
	})
	if err != nil {
		return nil, E.Cause(err, "create mtproto proxy")
	}

	in := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeMTProto, tag),
		ctx:     ctx,
		logger:  logger,
		proxy:   proxy,
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: in,
	})
	return in, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return i.listener.Start()
}

func (i *Inbound) Close() error {
	if i.proxy != nil {
		i.proxy.Shutdown()
	}
	return i.listener.Close()
}

// NewConnection serves one client connection through the MTProto proxy. ServeConn
// performs the full obfuscated handshake and relay synchronously; sing-box's
// listener already runs each connection in its own goroutine.
func (i *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	i.logger.InfoContext(ctx, "inbound mtproto connection from ", metadata.Source)
	i.proxy.ServeConn(essentialsConn{Conn: conn})
	if onClose != nil {
		onClose(nil)
	}
}
