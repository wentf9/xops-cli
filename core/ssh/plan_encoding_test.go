package ssh

import "testing"

func TestConnectionKeyPreservesBinaryCredentialVersions(t *testing.T) {
	plan := ConnectionPlan{Scope: "test", Hops: []ConnectionConfig{{NodeID: "node", Address: "localhost", User: "fixture", AuthUpdateToken: "\xff"}}}
	first, err := ConnectionKey(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Hops[0].AuthUpdateToken = "\xfe"
	second, err := ConnectionKey(plan)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("invalid UTF-8 credential versions collapsed into one pool key")
	}
	if plan.Hops[0].AuthUpdateToken != "\xfe" {
		t.Fatal("key generation mutated the supplied plan")
	}
}
