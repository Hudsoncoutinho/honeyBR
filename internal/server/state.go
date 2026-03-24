package server

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type SecurityEvent struct {
	Timestamp string  `json:"timestamp"`
	Type      string  `json:"type"`
	Severity  string  `json:"severity"`
	Source    string  `json:"source"`
	Target    string  `json:"target"`
	Lat       float64 `json:"lat"`
	Lng       float64 `json:"lng"`
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
	if ev.Type == "command_exec" {
		s.summary.SuspiciousCommands++
	}
	if ev.Type == "secret_access" {
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

func StartDemoStream(hub *Hub, state *State) {
	go func() {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		ticker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()

		types := []string{"secret_access", "command_exec", "outbound_connection"}
		severity := []string{"low", "medium", "high", "critical"}
		targets := []string{"/etc/shadow", ".aws/credentials", "nc -lvnp 4444", "curl http://malicious.example"}
		coords := [][2]float64{
			{-23.5505, -46.6333},
			{-27.5954, -48.5480},
			{-22.9068, -43.1729},
			{-30.0346, -51.2177},
		}

		for range ticker.C {
			c := coords[r.Intn(len(coords))]
			ev := SecurityEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Type:      types[r.Intn(len(types))],
				Severity:  severity[r.Intn(len(severity))],
				Source:    fmt.Sprintf("pod/honeybr-%02d", r.Intn(99)),
				Target:    targets[r.Intn(len(targets))],
				Lat:       c[0],
				Lng:       c[1],
			}
			sum := state.AddEvent(ev)
			msg, _ := json.Marshal(WSMessage{Event: ev, Summary: sum})
			hub.Broadcast(string(msg))
		}
	}()
}
