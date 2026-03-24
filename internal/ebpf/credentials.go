package ebpf

import "regexp"

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
