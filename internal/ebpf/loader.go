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
	Priority  int
	Source    string
	Target    string
	Node      string
	Namespace string
	Pod       string
	Container string
	CredentialType string
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

	seen := make(map[string]time.Time, 4096)
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

			for _, e := range entries {
				if !e.IsDir() {
					continue
				}
				pid, err := strconv.Atoi(e.Name())
				if err != nil {
					continue
				}
				l.emitFromPID(pid, index, seen)
			}

			now := time.Now()
			for key, ts := range seen {
				if now.Sub(ts) > 15*time.Minute {
					delete(seen, key)
				}
			}
		}
	}
}

func (l *Loader) emitFromPID(pid int, index *podIndex, seen map[string]time.Time) {
	cmd := readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if cmd == "" {
		cmd = readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	}
	cmd = strings.ReplaceAll(cmd, "\x00", " ")
	if cmd == "" {
		return
	}

	env := strings.ReplaceAll(readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "environ")), "\x00", " ")
	cgroup := readFileTrim(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	podUID, containerID := extractCgroupIDs(cgroup)
	meta := index.Resolve(podUID, containerID)

	for _, threat := range detectThreats(cmd, env) {
		if !isCICDNamespace(meta.Namespace) && threat.Severity != "critical" {
			// Keep focus on CI/CD runtime. Outside CI/CD, only critical findings are emitted.
			continue
		}

		ev := RuntimeEvent{
			Timestamp:      time.Now(),
			Type:           threat.Type,
			Severity:       threat.Severity,
			Priority:       threat.Priority,
			Source:         "pid/" + strconv.Itoa(pid),
			Target:         threat.Target,
			Node:           meta.Node,
			Namespace:      meta.Namespace,
			Pod:            meta.Pod,
			Container:      containerID,
			CredentialType: threat.CredentialType,
		}

		dedupKey := strconv.Itoa(pid) + "|" + ev.Type + "|" + ev.Target + "|" + ev.Namespace + "|" + ev.Pod
		if last, ok := seen[dedupKey]; ok && time.Since(last) < 60*time.Second {
			continue
		}
		seen[dedupKey] = time.Now()

		select {
		case l.events <- ev:
		default:
		}
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

type threatFinding struct {
	Type           string
	Severity       string
	Priority       int
	Target         string
	CredentialType string
}

func detectThreats(cmd, env string) []threatFinding {
	lc := strings.ToLower(cmd + " " + env)
	out := make([]threatFinding, 0, 4)

	switch {
	case strings.Contains(lc, "bash -i"), strings.Contains(lc, "nc "), strings.Contains(lc, "socat"), strings.Contains(lc, "curl http://"), strings.Contains(lc, "wget http://"):
		out = append(out, threatFinding{Type: "exfiltration_attempt", Severity: "critical", Priority: 95, Target: trimForUI(cmd)})
	}

	if strings.Contains(lc, "/etc/shadow") || strings.Contains(lc, ".aws/credentials") || strings.Contains(lc, "id_rsa") || strings.Contains(lc, "kube/config") {
		out = append(out, threatFinding{Type: "secret_file_access", Severity: "high", Priority: 80, Target: trimForUI(cmd)})
	}

	// Hardening: only trigger secret leaks when specific credential regex matches.
	payload := cmd + " " + env
	for _, m := range matchCredentialLeaks(payload) {
		out = append(out, threatFinding{
			Type:           "secret_env_exposure",
			Severity:       m.Severity,
			Priority:       m.Priority,
			CredentialType: m.CredentialType,
			Target:         trimForUI(m.RedactedValue),
		})
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

type credentialMatch struct {
	CredentialType string
	Severity       string
	Priority       int
	RedactedValue  string
}

var credentialRules = []struct {
	CredentialType string
	Severity       string
	Priority       int
	Regex          *regexp.Regexp
}{
	{
		CredentialType: "aws_access_key_id",
		Severity:       "high",
		Priority:       85,
		Regex:          regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
	},
	{
		CredentialType: "aws_secret_access_key",
		Severity:       "critical",
		Priority:       95,
		Regex:          regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+]{40})`),
	},
	{
		CredentialType: "github_pat",
		Severity:       "critical",
		Priority:       96,
		Regex:          regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`),
	},
	{
		CredentialType: "gitlab_pat",
		Severity:       "critical",
		Priority:       96,
		Regex:          regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
	},
	{
		CredentialType: "jwt_token",
		Severity:       "high",
		Priority:       82,
		Regex:          regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	},
}

func matchCredentialLeaks(payload string) []credentialMatch {
	out := make([]credentialMatch, 0, 2)
	seen := make(map[string]struct{})
	for _, rule := range credentialRules {
		matches := rule.Regex.FindAllString(payload, 3)
		for _, mv := range matches {
			key := rule.CredentialType + ":" + mv
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, credentialMatch{
				CredentialType: rule.CredentialType,
				Severity:       rule.Severity,
				Priority:       rule.Priority,
				RedactedValue:  redactSecret(mv),
			})
		}
	}
	return out
}

func redactSecret(v string) string {
	if len(v) <= 8 {
		return "[REDACTED]"
	}
	return v[:4] + "..." + v[len(v)-4:]
}

func isCICDNamespace(ns string) bool {
	ns = strings.ToLower(ns)
	return strings.Contains(ns, "gitlab") || strings.Contains(ns, "jenkins") || strings.Contains(ns, "argo") || strings.Contains(ns, "ci")
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
