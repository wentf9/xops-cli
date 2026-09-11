//go:build linux && (amd64 || arm64)

package kdfhelper

import (
	"path/filepath"
	"strconv"
	"strings"
)

type memoryFileReader func(string) ([]byte, error)

// cgroupMemoryAvailable resolves controller paths through mountinfo rather than
// assuming a host layout. It handles v1 memory controllers and unified v2.
func cgroupMemoryAvailable(groups, mounts string, read memoryFileReader) (available uint64, observed bool) {
	for _, line := range strings.Split(groups, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		version := 0
		if fields[0] == "0" && fields[1] == "" {
			version = 2
		} else if containsController(fields[1], "memory") {
			version = 1
		}
		if version == 0 {
			continue
		}
		for _, mount := range strings.Split(mounts, "\n") {
			root, point, ok := memoryMount(mount, version)
			if !ok {
				continue
			}
			group := fields[2]
			if !filepath.IsAbs(group) || filepath.Clean(group) != group {
				continue
			}
			rel, err := filepath.Rel(root, group)
			if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
				continue
			}
			path := filepath.Join(point, rel)
			if free, known := memoryAtHierarchy(path, point, version, read); known && (!observed || free < available) {
				available, observed = free, true
			}

		}
	}
	return available, observed
}

func memoryAtHierarchy(path, point string, version int, read memoryFileReader) (available uint64, observed bool) {
	first := true
	for {
		limitName, usedName := "memory.max", "memory.current"
		eligible := true
		if version == 1 {
			limitName, usedName = "memory.limit_in_bytes", "memory.usage_in_bytes"
			if !first {
				hierarchy, e := read(filepath.Join(path, "memory.use_hierarchy"))
				eligible = e == nil && strings.TrimSpace(string(hierarchy)) == "1"
			}
		}
		if eligible {
			max, maxErr := read(filepath.Join(path, limitName))
			used, usedErr := read(filepath.Join(path, usedName))
			unlimited := false
			if version == 1 {
				n, e := strconv.ParseUint(strings.TrimSpace(string(max)), 10, 64)
				unlimited = e == nil && n >= 1<<60
			}
			if maxErr == nil && usedErr == nil && !unlimited {
				if free, ok := cgroupRemaining(string(max), string(used)); ok && (!observed || free < available) {
					available, observed = free, true
				}
			}
		}
		if path == point {
			break
		}
		path = filepath.Dir(path)
		first = false
	}
	return available, observed
}

func containsController(list, name string) bool {
	for _, value := range strings.Split(list, ",") {
		if value == name {
			return true
		}
	}
	return false
}

func memoryMount(line string, version int) (root, point string, ok bool) {
	before, after, found := strings.Cut(line, " - ")
	if !found {
		return "", "", false
	}
	head, tail := strings.Fields(before), strings.Fields(after)
	if len(head) < 6 || len(tail) < 3 {
		return "", "", false
	}
	if version == 2 && tail[0] != "cgroup2" {
		return "", "", false
	}
	if version == 1 && (tail[0] != "cgroup" || !containsController(tail[2], "memory")) {
		return "", "", false
	}
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	root, point = unescape.Replace(head[3]), unescape.Replace(head[4])
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(point) || filepath.Clean(point) != point {
		return "", "", false
	}
	return root, point, true
}
