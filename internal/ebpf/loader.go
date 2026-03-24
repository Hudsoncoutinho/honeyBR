package ebpf

import "github.com/cilium/ebpf"

// Keeps github.com/cilium/ebpf in go.sum for bpf2go-generated code.
var _ ebpf.Program

type Loader struct{}

func NewLoader() (*Loader, error) {
	return &Loader{}, nil
}

func (l *Loader) Attach() error {
	return nil
}

func (l *Loader) Close() error {
	return nil
}
