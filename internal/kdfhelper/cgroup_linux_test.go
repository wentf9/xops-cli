//go:build linux && amd64

package kdfhelper

import (
	"os"
	"testing"
)

func TestCgroupMemoryCompatibility(t *testing.T) {
	tests := []struct {
		name, groups, mounts string
		files                map[string]string
		want                 uint64
		known                bool
	}{
		{"v1 limit", "3:memory:/service", "1 0 0:1 / /memory rw - cgroup cgroup rw,memory", map[string]string{"/memory/service/memory.limit_in_bytes": "100", "/memory/service/memory.usage_in_bytes": "80"}, 20, true},
		{"v2 namespaced mount", "0::/tenant/job", "1 0 0:1 /tenant /cg rw - cgroup2 cgroup rw", map[string]string{"/cg/job/memory.max": "200", "/cg/job/memory.current": "20", "/cg/memory.max": "100", "/cg/memory.current": "90"}, 10, true},
		{"v1 hierarchical parent", "3:memory:/job", "1 0 0:1 / /cg rw - cgroup cgroup rw,memory", map[string]string{"/cg/job/memory.limit_in_bytes": "100", "/cg/job/memory.usage_in_bytes": "10", "/cg/memory.limit_in_bytes": "50", "/cg/memory.usage_in_bytes": "45", "/cg/memory.use_hierarchy": "1"}, 5, true},
		{"v1 nonhierarchical parent", "3:memory:/job", "1 0 0:1 / /cg rw - cgroup cgroup rw,memory", map[string]string{"/cg/job/memory.limit_in_bytes": "100", "/cg/job/memory.usage_in_bytes": "10", "/cg/memory.limit_in_bytes": "50", "/cg/memory.usage_in_bytes": "45", "/cg/memory.use_hierarchy": "0"}, 90, true},
		{"v1 unlimited", "3:memory:/", "1 0 0:1 / /cg rw - cgroup cgroup rw,memory", map[string]string{"/cg/memory.limit_in_bytes": "9223372036854771712", "/cg/memory.usage_in_bytes": "10"}, 0, false},
		{"unrelated controller", "3:cpu:/", "1 0 0:1 / /cg rw - cgroup cgroup rw,cpu", nil, 0, false},
		{"outside mount root", "0::/other", "1 0 0:1 /tenant /cg rw - cgroup2 cgroup rw", nil, 0, false},
		{"escaped mount", "0::/", "1 0 0:1 / /my\\040cg rw - cgroup2 cgroup rw", map[string]string{"/my cg/memory.max": "100", "/my cg/memory.current": "99"}, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if value, ok := tt.files[path]; ok {
					return []byte(value), nil
				}
				return nil, os.ErrNotExist
			}
			got, known := cgroupMemoryAvailable(tt.groups, tt.mounts, read)
			if got != tt.want || known != tt.known {
				t.Fatalf("got %d/%t, want %d/%t", got, known, tt.want, tt.known)
			}
		})
	}
}
