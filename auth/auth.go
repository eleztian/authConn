package auth

import "errors"

type Credential interface {
	Detail() map[string]string
	Reset(map[string]string) error
}

type BasicCredential struct {
	Username string
	Password string
}

func (b *BasicCredential) Reset(m map[string]string) error {
	u, ok := m["U"]
	if !ok {
		return errors.New("not found username")
	}
	p, ok := m["P"]
	if !ok {
		return errors.New("not found password")
	}

	b.Username = u
	b.Password = p

	return nil
}

func (b BasicCredential) Detail() map[string]string {
	return map[string]string{
		"U": b.Username,
		"P": b.Password,
	}
}
