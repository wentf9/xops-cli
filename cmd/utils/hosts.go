package utils

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/wentf9/xops-cli/core/fsx"
)

const maxHostFileBytes int64 = 16 * 1024 * 1024 // 16 MiB

func readBoundedHostListFile(path, label string, maxBytes int64) ([]byte, error) {
	// User CLI input files (--host-file / --csv) follow symlinks like standard
	// POSIX tools while fsx.ReadAllBounded opens handle-first without
	// Stat-then-Open and rejects directories, FIFOs, devices, and oversized files.
	data, err := fsx.ReadAllBounded(path, fsx.Limits{MaxBytes: maxBytes}, fsx.FollowSymlinks())
	if err == nil {
		return data, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s %q not found: %w", label, path, err)
	}
	if errors.Is(err, fsx.ErrTooLarge) {
		return nil, fmt.Errorf("%s %q exceeds maximum size of %d bytes: %w", label, path, maxBytes, err)
	}
	if errors.Is(err, fsx.ErrNonRegular) {
		// Post-rejection diagnostic only (handle open already failed closed).
		if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
			return nil, fmt.Errorf("%s %q is a directory, expected a regular file: %w", label, path, err)
		}
		return nil, fmt.Errorf("%s %q must be a regular file: %w", label, path, err)
	}
	return nil, fmt.Errorf("read %s %q failed: %w", label, path, err)
}

// HostInfo 存储从CSV或参数中解析出的主机信息
type HostInfo struct {
	Host       string
	Port       uint16
	Alias      string
	User       string
	Password   string
	KeyPath    string
	Passphrase string
}

// ReadCSVFile 从指定路径读取CSV文件并解析为主机列表
func ReadCSVFile(path string) (hosts []HostInfo, err error) {
	if filepath.IsLocal(path) {
		wd, getwdErr := os.Getwd()
		if getwdErr != nil {
			return nil, fmt.Errorf("resolve csv file %q failed: %w", path, getwdErr)
		}
		path = filepath.Join(wd, path)
	}

	data, err := readBoundedHostListFile(path, "csv file", maxHostFileBytes)
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(bytes.NewReader(data))
	// 允许不一致的列数（可选，视CSV规范而定）
	reader.FieldsPerRecord = -1

	// 读取表头
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read csv header failed: %w", err)
	}

	mapping := buildCSVMapping(header)

	if mapping.host == -1 {
		return nil, fmt.Errorf("csv header must contain host/ip column")
	}

	rowNum := 1
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		rowNum++
		if err != nil {
			return nil, fmt.Errorf("csv row %d: read record failed: %w", rowNum, err)
		}

		hostInfo, ok, parseErr := parseHostRecord(record, mapping)
		if parseErr != nil {
			return nil, fmt.Errorf("csv row %d: %w", rowNum, parseErr)
		}
		if ok {
			hosts = append(hosts, hostInfo)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no valid host records found in csv file %q", path)
	}

	return hosts, nil
}

// ParseHosts 综合处理单主机、主机文件和CSV文件中的主机信息
func ParseHosts(ip, hostFile, csvFile string) ([]HostInfo, error) {
	var hosts []string
	var HostsInfo []HostInfo
	if csvFile != "" {
		var err error
		HostsInfo, err = ReadCSVFile(csvFile)
		if err != nil {
			return nil, err
		}
	} else {
		if ip != "" {
			parts := strings.Split(ip, ",")
			for _, p := range parts {
				hosts = append(hosts, strings.TrimSpace(p))
			}
		} else if hostFile != "" {
			file, err := readBoundedHostListFile(hostFile, "host file", maxHostFileBytes)
			if err != nil {
				return nil, fmt.Errorf("read host file %s failed: %w", hostFile, err)
			}
			lines := strings.Split(string(file), "\n")
			for i, line := range lines {
				if i == 0 {
					line = strings.TrimPrefix(line, "\uFEFF")
				}
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				hosts = append(hosts, line)
			}
		}
		for _, host := range hosts {
			u, h, p, err := ParseAddr(host)
			if err != nil {
				return nil, fmt.Errorf("invalid host address %q: %w", host, err)
			}
			HostsInfo = append(HostsInfo, HostInfo{
				Host: h,
				Port: p,
				User: u,
			})
		}
	}
	return HostsInfo, nil
}

type csvHostMapping struct {
	host, port, alias, user, pass, key, keyPass int
}

func buildCSVMapping(header []string) csvHostMapping {
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	findIdx := func(names ...string) int {
		for _, name := range names {
			if idx, ok := colMap[strings.ToLower(name)]; ok {
				return idx
			}
		}
		return -1
	}

	return csvHostMapping{
		host:    findIdx("host", "主机", "主机地址", "ip", "address"),
		port:    findIdx("port", "端口"),
		alias:   findIdx("alias", "别名", "name"),
		user:    findIdx("user", "用户", "用户名", "username"),
		pass:    findIdx("password", "密码", "登录密码"),
		key:     findIdx("key", "私钥", "私钥地址", "keypath", "identity_file"),
		keyPass: findIdx("keypass", "key_pass", "私钥密码", "passphrase"),
	}
}

func isRecordEmpty(record []string) bool {
	for _, field := range record {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

func parseHostRecord(record []string, mapping csvHostMapping) (HostInfo, bool, error) {
	if isRecordEmpty(record) {
		return HostInfo{}, false, nil
	}

	getVal := func(idx int) string {
		if idx != -1 && idx < len(record) {
			return strings.TrimSpace(record[idx])
		}
		return ""
	}

	hostStr := getVal(mapping.host)
	if hostStr == "" {
		return HostInfo{}, false, fmt.Errorf("host field is required")
	}

	inlineUser, host, port, err := ParseAddr(hostStr)
	if err != nil {
		return HostInfo{}, false, fmt.Errorf("parse host %q failed: %w", hostStr, err)
	}

	if pStr := getVal(mapping.port); pStr != "" {
		p, parseErr := ParsePort(pStr)
		if parseErr != nil {
			return HostInfo{}, false, fmt.Errorf("parse port %q failed: %w", pStr, parseErr)
		}
		port = p
	}

	user := getVal(mapping.user)
	if user == "" {
		user = inlineUser
	}

	return HostInfo{
		Host:       host,
		Port:       port,
		Alias:      getVal(mapping.alias),
		User:       user,
		Password:   getVal(mapping.pass),
		KeyPath:    getVal(mapping.key),
		Passphrase: getVal(mapping.keyPass),
	}, true, nil
}
