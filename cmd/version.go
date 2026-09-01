package cmd

import (
	"context"
	"fmt"

	"github.com/lesomnus/smb-exporter/cmd/version"
	"github.com/lesomnus/xli"
)

func NewCmdVersion() *xli.Command {
	return &xli.Command{
		Name: "version",
		Handler: xli.OnRun(func(ctx context.Context, cmd *xli.Command, next xli.Next) error {
			fmt.Fprintln(cmd, version.Get().Version)
			return next(ctx)
		}),
	}
}
