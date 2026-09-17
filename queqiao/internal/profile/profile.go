package profile

type Profile struct{}

func (p *Profile) HintedClass(identity string) (string, bool) {
	return "", false
}

func (p *Profile) ValidateHints() error { return nil }

type Config struct{}
