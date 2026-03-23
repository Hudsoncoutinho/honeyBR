package ebpf

type Loader struct{}

func NewLoader() (*Loader, error) {
	return &Loader{}, nil
}

func (l *Loader) Attach() error {
	return nil
}

func (l *Loader) Close() error {
	return nil
}
