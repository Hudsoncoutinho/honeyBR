# Contribuindo com o HoneyBR

Obrigado por querer contribuir.

## Fluxo recomendado

1. Crie uma branch a partir de `main`.
2. Implemente sua mudanca com testes.
3. Rode:
   - `go test ./...`
   - `go vet ./...`
4. Abra um Pull Request com contexto e plano de teste.

## Convencoes

- Mantenha mudancas pequenas e objetivas.
- Documente alteracoes importantes no `README.md`.
- Para alteracoes em eBPF, atualize `bpf/` e rode `./scripts/generate-bpf.sh`.
