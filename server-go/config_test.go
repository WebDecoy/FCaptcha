package main

import "testing"

func configEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestSigningSecretFailsClosed(t *testing.T) {
	for _, values := range []map[string]string{
		{},
		{"FCAPTCHA_SECRET": insecureDefaultSecret},
	} {
		if _, err := signingSecretFromEnv(configEnv(values)); err == nil {
			t.Fatalf("configuration %v should fail", values)
		}
	}
}

func TestSigningSecretAcceptsConfiguredSecret(t *testing.T) {
	got, err := signingSecretFromEnv(configEnv(map[string]string{"FCAPTCHA_SECRET": "a-real-deployment-secret"}))
	if err != nil || got != "a-real-deployment-secret" {
		t.Fatalf("got secret=%q err=%v", got, err)
	}
}

func TestSigningSecretExplicitDevelopmentMode(t *testing.T) {
	got, err := signingSecretFromEnv(configEnv(map[string]string{"FCAPTCHA_INSECURE_DEV_MODE": "yes"}))
	if err != nil || got != insecureDefaultSecret {
		t.Fatalf("got secret=%q err=%v", got, err)
	}
}
