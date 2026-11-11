package host

import (
	"bytes"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

func setupInventoryTestNodes(t *testing.T) {
	t.Helper()
	repo, _ := verificationRepository(t)

	nodes := []struct {
		id       string
		node     models.Node
		host     models.Host
		identity models.Identity
	}{
		{
			id: "local",
			node: models.Node{
				HostRef:     "h-local",
				IdentityRef: "id-local",
				Alias:       []string{"local"},
				Tags:        []string{"dev", "local-only"},
			},
			host:     models.Host{Address: "127.0.0.1", Port: 22},
			identity: models.Identity{User: "ops", AuthType: "password"},
		},
		{
			id: "localhost-box",
			node: models.Node{
				HostRef:     "h-lh",
				IdentityRef: "id-lh",
				Tags:        []string{"dev"},
			},
			host:     models.Host{Address: "localhost", Port: 2222},
			identity: models.Identity{User: "admin", AuthType: "key"},
		},
		{
			id: "ipv6-loopback",
			node: models.Node{
				HostRef:     "h-v6",
				IdentityRef: "id-v6",
				Tags:        []string{"v6"},
			},
			host:     models.Host{Address: "::1", Port: 22},
			identity: models.Identity{User: "root", AuthType: "key"},
		},
		{
			id: "remote-web",
			node: models.Node{
				HostRef:     "h-remote",
				IdentityRef: "id-remote",
				Tags:        []string{"prod"},
			},
			host:     models.Host{Address: "192.0.2.10", Port: 22},
			identity: models.Identity{User: "deploy", AuthType: "key"},
		},
	}

	for _, n := range nodes {
		if _, err := repo.CreateNodeContext(t.Context(), n.id, n.node, n.host, n.identity); err != nil {
			t.Fatalf("CreateNodeContext(%q) error: %v", n.id, err)
		}
	}
}

func parseInventoryRows(t *testing.T, output string) map[string]string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 1 {
		t.Fatalf("expected output with header, got empty output")
	}
	rows := make(map[string]string)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			rows[fields[0]] = line
		}
	}
	return rows
}

func TestInventoryList(t *testing.T) {
	setupInventoryTestNodes(t)

	t.Run("list all nodes", func(t *testing.T) {
		cmd := NewCmdInventoryList()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs(nil)
		cmd.SetContext(t.Context())

		if err := cmd.Execute(); err != nil {
			t.Fatalf("cmd.Execute() error: %v", err)
		}

		rows := parseInventoryRows(t, out.String())
		if len(rows) != 4 {
			t.Fatalf("expected 4 node rows, got %d; full output:\n%s", len(rows), out.String())
		}

		expectedNodes := map[string]string{
			"local":         "127.0.0.1:22",
			"localhost-box": "localhost:2222",
			"ipv6-loopback": "::1:22",
			"remote-web":    "192.0.2.10:22",
		}
		for nodeID, expectedEndpoint := range expectedNodes {
			line, exists := rows[nodeID]
			if !exists {
				t.Errorf("node %q missing from inventory list rows; full output:\n%s", nodeID, out.String())
				continue
			}
			if !strings.Contains(line, expectedEndpoint) {
				t.Errorf("node %q row %q does not contain endpoint %q", nodeID, line, expectedEndpoint)
			}
		}
	})

	t.Run("list nodes filtered by tag", func(t *testing.T) {
		cmd := NewCmdInventoryList()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(new(bytes.Buffer))
		cmd.SetArgs([]string{"--tag", "dev"})
		cmd.SetContext(t.Context())

		if err := cmd.Execute(); err != nil {
			t.Fatalf("cmd.Execute() error: %v", err)
		}

		rows := parseInventoryRows(t, out.String())
		if len(rows) != 2 {
			t.Fatalf("expected 2 node rows for tag dev, got %d; full output:\n%s", len(rows), out.String())
		}

		if line, exists := rows["local"]; !exists {
			t.Errorf("node 'local' missing from filtered rows; full output:\n%s", out.String())
		} else if !strings.Contains(line, "127.0.0.1:22") {
			t.Errorf("node 'local' row %q does not contain 127.0.0.1:22", line)
		}

		if line, exists := rows["localhost-box"]; !exists {
			t.Errorf("node 'localhost-box' missing from filtered rows; full output:\n%s", out.String())
		} else if !strings.Contains(line, "localhost:2222") {
			t.Errorf("node 'localhost-box' row %q does not contain localhost:2222", line)
		}

		for _, dontWant := range []string{"remote-web", "ipv6-loopback"} {
			if _, exists := rows[dontWant]; exists {
				t.Errorf("node %q unexpectedly found in filtered rows; full output:\n%s", dontWant, out.String())
			}
		}
	})
}

func TestInventoryTags(t *testing.T) {
	setupInventoryTestNodes(t)

	cmd := NewCmdInventoryTags()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs(nil)
	cmd.SetContext(t.Context())

	if err := cmd.Execute(); err != nil {
		t.Fatalf("cmd.Execute() error: %v", err)
	}

	output := out.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected header and tags in output, got:\n%s", output)
	}

	tagCounts := make(map[string]string)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			tagCounts[fields[0]] = fields[1]
		}
	}

	expected := map[string]string{
		"dev":        "2",
		"local-only": "1",
		"v6":         "1",
		"prod":       "1",
	}
	for tag, wantCount := range expected {
		gotCount, exists := tagCounts[tag]
		if !exists {
			t.Errorf("tag %q missing in output:\n%s", tag, output)
			continue
		}
		if gotCount != wantCount {
			t.Errorf("tag %q count = %q, want %q; output:\n%s", tag, gotCount, wantCount, output)
		}
	}
}
