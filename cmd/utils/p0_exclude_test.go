package utils

import (
	"slices"
	"testing"

	"github.com/spf13/pflag"
)

func TestP0_ValidateExcludeFlagValues(t *testing.T) {
	t.Parallel()

	invalidCases := []struct {
		name string
		raw  []string
	}{
		{"nil", nil},
		{"empty_slice", []string{}},
		{"empty_string", []string{""}},
		{"whitespace_only", []string{"   "}},
		{"tab_only", []string{"\t"}},
		{"comma_only", []string{","}},
		{"double_comma", []string{",,"}},
		{"empty_middle_segment", []string{"web1,,web2"}},
		{"whitespace_middle_segment", []string{"web1, ,web2"}},
		{"trailing_comma", []string{"web1,"}},
		{"leading_comma", []string{",web1"}},
		{"valid_followed_by_empty", []string{"web1", ""}},
		{"valid_followed_by_whitespace", []string{"web1", "  "}},
	}
	for _, tc := range invalidCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			if got, err := ValidateExcludeFlagValues(tc.raw); err == nil {
				t.Fatalf("ValidateExcludeFlagValues(%q) = (%v, nil), expected error", tc.raw, got)
			}
		})
	}

	validCases := []struct {
		name string
		raw  []string
		want []string
	}{
		{"single", []string{"web1"}, []string{"web1"}},
		{"comma_list", []string{"web1,web2"}, []string{"web1", "web2"}},
		{"trimmed_dedup", []string{" web1 , web2 ", "web1"}, []string{"web1", "web2"}},
		{"ipv6_and_alias", []string{"ops@[2001:db8::1]:2222,db-01"}, []string{"ops@[2001:db8::1]:2222", "db-01"}},
	}
	for _, tc := range validCases {
		t.Run("accept_"+tc.name, func(t *testing.T) {
			got, err := ValidateExcludeFlagValues(tc.raw)
			if err != nil {
				t.Fatalf("ValidateExcludeFlagValues(%q) unexpected error: %v", tc.raw, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ValidateExcludeFlagValues(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestP0_RegisterExcludeFlag_CapturesEmptyAndPreservesStringSlice(t *testing.T) {
	t.Parallel()

	t.Run("valid_flags_preserve_GetStringSlice", func(t *testing.T) {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		var excludes []string
		RegisterExcludeFlag(fs, &excludes, "exclude hosts")

		if err := fs.Parse([]string{"--exclude", "web1,web2", "--exclude", "db1"}); err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		gotSlice, err := fs.GetStringSlice("exclude")
		if err != nil {
			t.Fatalf("GetStringSlice failed: %v", err)
		}
		if !slices.Equal(gotSlice, []string{"web1", "web2", "db1"}) {
			t.Fatalf("GetStringSlice = %v, want [web1 web2 db1]", gotSlice)
		}
		validated, err := ValidateExcludeFlagValues(excludes)
		if err != nil {
			t.Fatalf("ValidateExcludeFlagValues(%v) failed: %v", excludes, err)
		}
		if !slices.Equal(validated, []string{"web1", "web2", "db1"}) {
			t.Fatalf("validated = %v, want [web1 web2 db1]", validated)
		}
	})

	t.Run("repeated_empty_flag_rejected_in_parse", func(t *testing.T) {
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		var excludes []string
		RegisterExcludeFlag(fs, &excludes, "exclude hosts")

		if err := fs.Parse([]string{"--exclude", "web1", "--exclude", ""}); err == nil {
			t.Fatalf("expected Parse to reject repeated empty --exclude, got excludes=%v", excludes)
		}
	})
}
