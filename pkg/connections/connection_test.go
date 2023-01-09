package connections

import "testing"

func TestNewConnectionString(t *testing.T) {

	wellformed := `ssh://user:pass@127.0.0.1:22`

	cs, err := NewConnectionString(wellformed)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if cs.Scheme != "ssh" {
		t.Fatalf(`expected "ssh://", got %v`, cs.Scheme)
	}

	if cs.Username != "user" {
		t.Fatalf(`expected "user", got %v`, cs.Username)
	}

	if cs.Password != "pass" {
		t.Fatalf(`expected "pass", got %v`, cs.Password)
	}

	if cs.Host != "127.0.0.1" {
		t.Fatalf(`expected "127.0.0.1", got %v`, cs.Host)
	}

	if cs.Port != "22" {
		t.Fatalf(`expected "22", got %v`, cs.Port)
	}

	var (
		malformedScheme string = `sshs://user:pass@example.com:22`
		malformedPort   string = `winrm://user:pass@example.com`
	)

	_, err = NewConnectionString(malformedScheme)
	if err == nil {
		t.Fatalf(`expected error from malformed scheme in: %v`, malformedScheme)
	}

	_, err = NewConnectionString(malformedPort)
	if err == nil {
		t.Fatalf(`expected error from malformed port in: %v`, malformedPort)
	}
}

func TestNewConnection(t *testing.T) {

}
