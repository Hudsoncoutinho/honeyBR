//go:build linux && ebpfgen

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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
	stopCh chan struct{}
	wg     sync.WaitGroup
	rules  *config.Rules

	collection *honeybrObjects
	links      []link.Link
	reader     *ringbuf.Reader
}

type bpfEvent struct {
	TsNs     uint64
	Pid      uint32
	Tgid     uint32
	CgroupID uint64
	Type     uint32
	Dport    int32
	Comm     [16]byte
	Filename [256]byte
}

const (
	eventExecve  = 1
	eventOpenat  = 2
	eventConnect = 3
)

func NewLoader(rules *config.Rules) (*Loader, error) {
	return &Loader{
		events: make(chan RuntimeEvent, 1024),
		stopCh: make(chan struct{}),
		rules:  rules,
	}, nil
}

func (l *Loader) Attach() error {
	var objs honeybrObjects
	if err := loadHoneybrObjects(&objs, nil); err != nil {
		return err
	}
	l.collection = &objs

	execLnk, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		return err
	}
	openLnk, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		execLnk.Close()
		return err
	}
	connectLnk, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		execLnk.Close()
		openLnk.Close()
		return err
	}
	l.links = []link.Link{execLnk, openLnk, connectLnk}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, lk := range l.links {
			_ = lk.Close()
		}
		return err
	}
	l.reader = rd

	l.wg.Add(1)
	go l.readLoop()
	return nil
}

func (l *Loader) Close() error {
	close(l.stopCh)
	if l.reader != nil {
		_ = l.reader.Close()
	}
	for _, lk := range l.links {
		_ = lk.Close()
	}
	if l.collection != nil {
		l.collection.Close()
	}
	l.wg.Wait()
	close(l.events)
	return nil
}

func (l *Loader) Events() <-chan RuntimeEvent {
	return l.events
}

func (l *Loader) readLoop() {
	defer l.wg.Done()

	index := newPodIndex()
	index.Start(l.stopCh)
	seen := make(map[string]time.Time, 4096)

	for {
		select {
		case <-l.stopCh:
			return
		default:
		}

		record, err := l.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var raw bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		l.emitKernelEvent(raw, index, seen)
	}
}

func (l *Loader) emitKernelEvent(raw bpfEvent, index *podIndex, seen map[string]time.Time) {
	filename := trimCString(raw.Filename[:])
	comm := trimCString(raw.Comm[:])
	pidStr := strconv.Itoa(int(raw.Tgid))
	cgroup := readFileTrim(filepath.Join("/proc", pidStr, "cgroup"))
	podUID, containerID := extractCgroupIDs(cgroup)
	meta := index.Resolve(podUID, containerID)

	findings := classifyKernelFinding(raw, filename, comm, l.rules)
	if len(findings) == 0 {
		return
	}

	for _, f := range findings {
		ev := RuntimeEvent{
			Timestamp:      time.Now(),
			Type:           f.Type,
			Severity:       f.Severity,
			Priority:       f.Priority,
			CredentialType: f.CredentialType,
			Source:         "pid/" + pidStr + " (" + comm + ")",
			Target:         f.Target,
			Node:           meta.Node,
			Namespace:      meta.Namespace,
			Pod:            meta.Pod,
			Container:      containerID,
		}

		key := ev.Source + "|" + ev.Type + "|" + ev.Target + "|" + ev.Namespace + "|" + ev.Pod
		if last, ok := seen[key]; ok && time.Since(last) < 30*time.Second {
			continue
		}
		seen[key] = time.Now()

		select {
		case l.events <- ev:
		default:
		}
	}
}

type kernelFinding struct {
	Type           string
	Severity       string
	Priority       int
	CredentialType string
	Target         string
}

func classifyKernelFinding(raw bpfEvent, filename, comm string, rules *config.Rules) []kernelFinding {
	out := make([]kernelFinding, 0, 3)
	lc := strings.ToLower(filename + " " + comm)

	switch raw.Type {
	case eventExecve:
		if strings.Contains(lc, "nc") || strings.Contains(lc, "socat") || strings.Contains(lc, "bash") || strings.Contains(lc, "curl") || strings.Contains(lc, "wget") {
			out = append(out, kernelFinding{Type: "exfiltration_attempt", Severity: "critical", Priority: 95, Target: trimForUI(filename)})
		}
	case eventOpenat:
		if strings.Contains(lc, "/etc/shadow") || strings.Contains(lc, ".aws/credentials") || strings.Contains(lc, "id_rsa") || strings.Contains(lc, "kube/config") {
			out = append(out, kernelFinding{Type: "secret_file_access", Severity: "high", Priority: 85, Target: trimForUI(filename)})
		}
		if rules != nil {
			for _, p := range rules.SensitivePaths {
				pp := strings.ToLower(strings.TrimSpace(p))
				if pp != "" && strings.Contains(lc, pp) {
					out = append(out, kernelFinding{Type: "secret_file_access", Severity: "high", Priority: 88, Target: trimForUI(filename)})
					break
				}
			}
		}
	case eventConnect:
		if raw.Dport > 0 {
			portS := strconv.Itoa(int(raw.Dport))
			if isPortSuspicious(raw.Dport, rules) {
				out = append(out, kernelFinding{
					Type:     "suspicious_port_activity",
					Severity: "critical",
					Priority: 92,
					Target:   "connect:" + portS,
				})
			}
		}
	}

	return out
}

func isPortSuspicious(port int32, rules *config.Rules) bool {
	if port == 4444 || port == 1337 || port == 31337 || port == 6666 {
		return true
	}
	if rules != nil {
		for _, p := range rules.SuspiciousPorts {
			if int(port) == p {
				return true
			}
		}
	}
	return false
}

func trimCString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return strings.TrimSpace(string(b[:n]))
}

func readFileTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func trimForUI(v string) string {
	if len(v) <= 200 {
		return v
	}
	return v[:200] + "..."
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
