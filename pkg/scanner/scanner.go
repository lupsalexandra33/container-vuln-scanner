package scanner

import (
	"context"

	"github.com/lupsalexandra33/container-vuln-scanner/pkg/model"
)

// Scanner is the minimal contract that every scanner must satisfy regardless of
// whether it is a local binary, a hosted service, or an in-process library call.
type Scanner interface {
	Name() string
	Version(ctx context.Context) (model.ToolVersion, error)
	Capabilities() model.Capabilities
	Available(ctx context.Context) error
	Scan(ctx context.Context, target model.Target) (model.RawResult, error)
}
