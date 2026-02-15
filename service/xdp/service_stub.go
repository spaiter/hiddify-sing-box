//go:build !(with_xdp && linux)

package xdp

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.XDPBlockerServiceOptions](registry, C.TypeXDPBlocker, func(ctx context.Context, logger log.ContextLogger, tag string, options option.XDPBlockerServiceOptions) (adapter.Service, error) {
		return nil, E.New("XDP blocker is only supported on Linux with -tags with_xdp")
	})
}
