package utils

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("csv file %q not found: %w", path, err)
		}
		return nil, fmt.Errorf("open csv file %q failed: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close csv file %q failed: %w", path, closeErr))
		}
	}()

	reader := csv.NewReader(file)
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
			file, err := os.ReadFile(hostFile)
			if err != nil {
				return nil, fmt.Errorf("read host file %s failed: %w", hostFile, err)
			}
			lines := strings.Split(string(file), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					hosts = append(hosts, line)
				}
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

	host, port, err := ParseHost(hostStr)
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

	return HostInfo{
		Host:       host,
		Port:       port,
		Alias:      getVal(mapping.alias),
		User:       getVal(mapping.user),
		Password:   getVal(mapping.pass),
		KeyPath:    getVal(mapping.key),
		Passphrase: getVal(mapping.keyPass),
	}, true, nil
}
