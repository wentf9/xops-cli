package cmd

import (
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

// selectorFlag is a pflag.Value for CLI target/selector flags (--host, --tag,
// --ifile, --limit) that rejects empty and whitespace-only values directly in
// Set(), preventing silent fallback to positional arguments or default targets.
type selectorFlag struct {
	target         *string
	flagName       string
	commaSeparated bool
}

func (f *selectorFlag) String() string {
	if f == nil || f.target == nil {
		return ""
	}
	return *f.target
}

func (f *selectorFlag) Type() string {
	return "string"
}

func (f *selectorFlag) Set(val string) error {
	if err := validateSelectorValue(f.flagName, val, f.commaSeparated); err != nil {
		return err
	}
	if f.target != nil {
		*f.target = val
	}
	return nil
}

func validateSelectorValue(flagName, val string, commaSeparated bool) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("flag --%s must not be empty", flagName)
	}
	if !commaSeparated {
		return nil
	}
	for _, part := range strings.Split(val, ",") {
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("invalid --%s %q: empty target segment", flagName, val)
		}
	}
	return nil
}

func registerSelectorFlag(flags *pflag.FlagSet, target *string, name, shorthand, usage string) {
	val := &selectorFlag{
		target:   target,
		flagName: name,
	}
	if shorthand != "" {
		flags.VarP(val, name, shorthand, usage)
		return
	}
	flags.Var(val, name, usage)
}

func registerCommaSelectorFlag(flags *pflag.FlagSet, target *string, name, shorthand, usage string) {
	val := &selectorFlag{
		target:         target,
		flagName:       name,
		commaSeparated: true,
	}
	if shorthand != "" {
		flags.VarP(val, name, shorthand, usage)
		return
	}
	flags.Var(val, name, usage)
}

// selectorSliceFlag wraps pflag's stringSlice value so empty, whitespace-only,
// and empty comma-separated segments are rejected directly in Set/Append/Replace.
type selectorSliceFlag struct {
	innerVal pflag.Value
	innerSlc pflag.SliceValue
	flagName string
}

func registerSelectorSliceFlag(flags *pflag.FlagSet, target *[]string, name, usage string) {
	flags.StringSliceVar(target, name, nil, usage)
	f := flags.Lookup(name)
	if f == nil {
		return
	}
	sv, ok := f.Value.(pflag.SliceValue)
	if !ok {
		return
	}
	f.Value = &selectorSliceFlag{
		innerVal: f.Value,
		innerSlc: sv,
		flagName: name,
	}
}

func (f *selectorSliceFlag) String() string { return f.innerVal.String() }
func (f *selectorSliceFlag) Type() string   { return f.innerVal.Type() }

func validateSelectorSliceCSV(flagName, val string) error {
	if strings.TrimSpace(val) == "" {
		return fmt.Errorf("flag --%s must not be empty", flagName)
	}
	records, err := csv.NewReader(strings.NewReader(val)).Read()
	if err != nil {
		return fmt.Errorf("invalid --%s %q: %w", flagName, val, err)
	}
	if len(records) == 0 {
		return fmt.Errorf("flag --%s must not be empty", flagName)
	}
	for _, item := range records {
		if strings.TrimSpace(item) == "" {
			return fmt.Errorf("invalid --%s %q: empty target segment", flagName, val)
		}
	}
	return nil
}

func (f *selectorSliceFlag) Set(val string) error {
	if err := validateSelectorSliceCSV(f.flagName, val); err != nil {
		return err
	}
	return f.innerVal.Set(val)
}

func (f *selectorSliceFlag) Append(val string) error {
	if err := validateSelectorSliceCSV(f.flagName, val); err != nil {
		return err
	}
	return f.innerSlc.Append(val)
}

func (f *selectorSliceFlag) Replace(vals []string) error {
	if len(vals) == 0 {
		return fmt.Errorf("flag --%s must not be empty", f.flagName)
	}
	for _, val := range vals {
		if err := validateSelectorSliceCSV(f.flagName, val); err != nil {
			return err
		}
	}
	return f.innerSlc.Replace(vals)
}

func (f *selectorSliceFlag) GetSlice() []string { return f.innerSlc.GetSlice() }

type selectorField struct {
	name string
	val  string
}

// validateProgrammaticSelectors rejects whitespace-only selector fields set
// directly on option structs outside pflag parsing.
func validateProgrammaticSelectors(fields ...selectorField) error {
	for _, f := range fields {
		if f.val != "" && strings.TrimSpace(f.val) == "" {
			return fmt.Errorf("flag --%s must not be empty", f.name)
		}
	}
	return nil
}
