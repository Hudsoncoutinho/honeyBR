package server

import (
	"strings"
	"sync"
)

type SecurityEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Node      string `json:"node"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

type Summary struct {
	TotalEvents        int `json:"totalEvents"`
	CriticalEvents     int `json:"criticalEvents"`
	SuspiciousCommands int `json:"suspiciousCommands"`
	SecretAccess       int `json:"secretAccess"`
}

type WSMessage struct {
	Event   SecurityEvent `json:"event"`
	Summary Summary       `json:"summary"`
}

type State struct {
	mu      sync.RWMutex
	events  []SecurityEvent
	summary Summary
}

func NewState() *State {
	return &State{
		events: make([]SecurityEvent, 0, 128),
	}
}

func (s *State) AddEvent(ev SecurityEvent) Summary {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append([]SecurityEvent{ev}, s.events...)
	if len(s.events) > 100 {
		s.events = s.events[:100]
	}

	s.summary.TotalEvents++
	if ev.Severity == "critical" {
		s.summary.CriticalEvents++
	}
	if ev.Type == "command_exec" || ev.Type == "exfiltration_attempt" {
		s.summary.SuspiciousCommands++
	}
	if strings.Contains(ev.Type, "secret_") {
		s.summary.SecretAccess++
	}

	return s.summary
}

func (s *State) Snapshot() (Summary, []SecurityEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]SecurityEvent, len(s.events))
	copy(out, s.events)
	return s.summary, out
}
