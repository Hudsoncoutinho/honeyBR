# HoneyBR

Monitor de seguranca runtime com Go e eBPF para Kubernetes.

## Execucao local

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@latest
./scripts/generate-bpf.sh
go build -o honeybr ./cmd/honeybr
sudo ./honeybr --rules=rules.yaml
```

## Kubernetes

```bash
helm install honeybr ./charts/honeybr -n kube-system
kubectl port-forward svc/honeybr-dashboard 8080:8080 -n kube-system
```

## Licenca

MIT.
