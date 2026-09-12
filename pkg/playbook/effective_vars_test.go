package playbook

import "testing"

func TestEffectiveVarsSharedWithRuntime(t *testing.T) {
	p := Playbook{Vars: map[string]string{"marker": "default"}, Steps: []Step{{Shell: "echo {{.marker}} {{.added}}"}}}
	overrides := map[string]string{"marker": "override", "added": "new"}
	if err := p.renderVars(overrides); err != nil {
		t.Fatal(err)
	}
	if p.Steps[0].Shell != "echo override new" || p.Vars["marker"] != "override" || p.Vars["added"] != "new" {
		t.Fatalf("inconsistent effective variables: %+v", p)
	}
	overrides["marker"] = "mutated"
	if p.Vars["marker"] != "override" {
		t.Fatal("variables alias caller map")
	}
}

func TestMissingVarsWithoutDefaults(t *testing.T) {
	p := Playbook{Steps: []Step{{Shell: "echo {{.missing}}"}}}
	if err := p.renderVars(nil); err == nil {
		t.Fatal("missing variable accepted")
	}
}
