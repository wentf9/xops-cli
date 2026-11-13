package ssh

import (
	"slices"
	"testing"
)

func TestResolveSessionEnv_SetEnvEnforcesHardDenylist(t *testing.T) {
	opts := &Options{}
	directives := []string{
		"ALLOWED_ONE=alpha",
		"XOPS_SECRET_TOKEN=leak1",
		"SSH_ASKPASS=/tmp/evil",
		"SSH_ASKPASS_REQUIRE=force",
		"SSH_AUTH_SOCK=/tmp/rogue.sock",
		"LD_PRELOAD=/tmp/evil.so",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"AWS_SECRET_ACCESS_KEY=leak2",
		"GITHUB_TOKEN=leak3",
		"ALLOWED_TWO=beta",
		"xops_lowercase_secret=leak4",
	}
	for _, d := range directives {
		if err := opts.Append(OptionSetEnv, d); err != nil {
			t.Fatalf("Append(SetEnv, %q) failed: %v", d, err)
		}
	}

	resolved, err := ResolveSessionEnv(opts, func() []string { return nil })
	if err != nil {
		t.Fatalf("ResolveSessionEnv failed: %v", err)
	}

	want := []EnvVar{
		{Name: "ALLOWED_ONE", Value: "alpha"},
		{Name: "ALLOWED_TWO", Value: "beta"},
	}
	if !slices.Equal(resolved, want) {
		t.Fatalf("ResolveSessionEnv = %+v, want %+v", resolved, want)
	}
}
