package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Rules struct {
	SensitivePaths  []string `yaml:"sensitive_paths"`
	SuspiciousPorts []int    `yaml:"suspicious_ports"`
}

func Load(path string) (*Rules, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Rules
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
