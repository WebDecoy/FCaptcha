package main

import "testing"

func configEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestSigningSecretFailsClosed(t *testing.T) {
	for _, values := range []map[string]string{
		{},
		{"FCAPTCHA_SECRET": insecureDefaultSecret},
		{"FCAPTCHA_SECRET": "x"},
		{"FCAPTCHA_SECRET": "my-secret"},
		{"FCAPTCHA_SECRET": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	} {
		if _, err := signingSecretFromEnv(configEnv(values)); err == nil {
			t.Fatalf("configuration %v should fail", values)
		}
	}
}

func TestSigningSecretAcceptsConfiguredSecret(t *testing.T) {
	got, err := signingSecretFromEnv(configEnv(map[string]string{"FCAPTCHA_SECRET": "a-real-deployment-secret-0123456789abcdef0123456789abcdef"}))
	if err != nil || got != "a-real-deployment-secret-0123456789abcdef0123456789abcdef" {
		t.Fatalf("got secret=%q err=%v", got, err)
	}
}

func TestSigningSecretExplicitDevelopmentMode(t *testing.T) {
	got, err := signingSecretFromEnv(configEnv(map[string]string{"FCAPTCHA_INSECURE_DEV_MODE": "yes"}))
	if err != nil || got != insecureDefaultSecret {
		t.Fatalf("got secret=%q err=%v", got, err)
	}
}
