package ebpf

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// Keeps github.com/cilium/ebpf in go.sum for bpf2go-generated code.
var _ ebpf.Program

type RuntimeEvent struct {
	Timestamp time.Time
	Type      string
	Severity  string
	Source    string
	Target    string
	Node      string
	Namespace string
	Pod       string
	Container string
}

type podInfo struct {
	Namespace string
	Pod       string
	Node      string
}

type Loader struct {
	events chan RuntimeEvent
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewLoader() (*Loader, error) {
	return &Loader{
		events: make(chan RuntimeEvent, 256),
		stopCh: make(chan struct{}),
	}, nil
}

func (l *Loader) Attach() error {
	l.wg.Add(1)
	go l.procStream()
	return nil
}

func (l *Loader) Close() error {
	close(l.stopCh)
	l.wg.Wait()
	close(l.events)
	return nil
}

func (l *Loader) Events() <-chan RuntimeEvent {
	return l.events
}

func (l *Loader) procStream() {
	defer l.wg.Done()

	index := newPodIndex()
	index.Start(l.stopCh)

	seen := make(map[int]struct{}, 2048)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			entries, err := os.ReadDir("/proc")
			if err != nil {
				continue
			}

			current := make(map[int]struct{}, len(entries))
			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				pid, err := strconv.Atoi(e.Name())
				if err != nil {
					continue
				}
				current[pid] = struct{}{}
				if _, ok := seen[pid]; ok {
					continue
				}
				seen[pid] = struct{}{}
				l.emitFromPID(pid, index)
			}

			for pid := range seen {
				if _, ok := current[pid]; !ok {
					delete(seen, pid)
				}
			}
		}
	}
}

func (l *Loader) emitFromPID(pid int, index *podIndex) {
	cmd := readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if cmd == "" {
		cmd = readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	}
	cmd = strings.ReplaceAll(cmd, "\x00", " ")
	if cmd == "" {
		return
	}

	sev := classifySeverity(cmd)
	cgroup := readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	podUID, containerID := extractCgroupIDs(cgroup)
	meta := index.Resolve(podUID, containerID)

	ev := RuntimeEvent{
		Timestamp: time.Now(),
		Type:      "command_exec",
		Severity:  sev,
		Source:    "pid/" + strconv.Itoa(pid),
		Target:    trimForUI(cmd),
		Node:      meta.Node,
		Namespace: meta.Namespace,
		Pod:       meta.Pod,
		Container: containerID,
	}

	select {
	case l.events <- ev:
	default:
	}
}

func readFileTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func trimForUI(v string) string {
	if len(v) <= 180 {
		return v
	}
	return v[:180] + "..."
}

func classifySeverity(cmd string) string {
	lc := strings.ToLower(cmd)
	switch {
	case strings.Contains(lc, "bash -i"), strings.Contains(lc, "nc "), strings.Contains(lc, "socat"), strings.Contains(lc, "curl http://"), strings.Contains(lc, "wget http://"):
		return "critical"
	case strings.Contains(lc, "kubectl"), strings.Contains(lc, "ssh"), strings.Contains(lc, "cat /etc/shadow"), strings.Contains(lc, ".aws/credentials"):
		return "high"
	default:
		return "medium"
	}
}

var (
	rePodUID      = regexp.MustCompile(`pod([0-9a-f_\\-]{20,})`)
	reContainerID = regexp.MustCompile(`([0-9a-f]{64})`)
)

func extractCgroupIDs(cgroup string) (podUID string, containerID string) {
	m := rePodUID.FindStringSubmatch(cgroup)
	if len(m) > 1 {
		podUID = strings.ReplaceAll(m[1], "_", "-")
	}
	m2 := reContainerID.FindStringSubmatch(cgroup)
	if len(m2) > 1 {
		containerID = m2[1]
	}
	return podUID, containerID
}
