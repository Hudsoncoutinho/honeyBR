//go:build !linux

package ebpf

import (
	"time"

	"github.com/hudsoncoutinho/honeybr/internal/config"
)

type RuntimeEvent struct {
	Timestamp      time.Time
	Type           string
	Severity       string
	Priority       int
	CredentialType string
	Source         string
	Target         string
	Node           string
	Namespace      string
	Pod            string
	Container      string
}

type Loader struct {
	events chan RuntimeEvent
}

func NewLoader(_ *config.Rules) (*Loader, error) {
	return &Loader{events: make(chan RuntimeEvent)}, nil
}

func (l *Loader) Attach() error { return nil }
func (l *Loader) Close() error {
	close(l.events)
	return nil
}
func (l *Loader) Events() <-chan RuntimeEvent { return l.events }
