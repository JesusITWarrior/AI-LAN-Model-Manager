package observation

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

const maxCommandOutput = 1024 * 1024

var (
	ErrAcceleratorOutput = errors.New("accelerator probe output exceeded limit")
	ErrNoAccelerators    = errors.New("no accelerators present")
)

type CommandRunner interface {
	Run(context.Context, string, []string) ([]byte, error)
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		b.exceeded = true
		return len(p), ErrAcceleratorOutput
	}
	return b.Buffer.Write(p)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, path string, args []string) ([]byte, error) {
	buffer := &boundedBuffer{limit: maxCommandOutput}
	command := exec.CommandContext(ctx, path, args...)
	command.Stdout, command.Stderr = buffer, buffer
	err := command.Run()
	if buffer.exceeded {
		return nil, ErrAcceleratorOutput
	}
	if err != nil {
		return buffer.Bytes(), err
	}
	return buffer.Bytes(), nil
}
