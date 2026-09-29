//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func runPlatformService(run func(context.Context) int) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx)
}
