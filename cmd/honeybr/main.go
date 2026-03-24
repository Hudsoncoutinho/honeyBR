package main

import (
	"flag"
	"log"

	"github.com/hudsoncoutinho/honeybr/internal/config"
	"github.com/hudsoncoutinho/honeybr/internal/ebpf"
	"github.com/hudsoncoutinho/honeybr/internal/server"
)

func main() {
	rulesPath := flag.String("rules", "rules.yaml", "path to rules file")
	addr := flag.String("addr", ":8080", "HTTP server address")
	flag.Parse()

	cfg, err := config.Load(*rulesPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	loader, err := ebpf.NewLoader()
	if err != nil {
		log.Fatalf("failed to initialize ebpf loader: %v", err)
	}
	defer loader.Close()

	if err := loader.Attach(); err != nil {
		log.Fatalf("failed to attach ebpf programs: %v", err)
	}

	srv := server.New(cfg, loader.Events())
	log.Printf("honeyBR dashboard listening on %s", *addr)
	if err := srv.Listen(*addr); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}
