package ssh

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// DiskMetric 存储单个分区的指标
type DiskMetric struct {
	MountPoint string
	Total      uint64 // MB
	Used       uint64 // MB
	Usage      float64
}

// SystemMetrics 给 TUI 展示用的整理后指标
type SystemMetrics struct {
	CPUUsage     float64
	Cores        int
	MemTotal     uint64
	MemUsed      uint64
	MemUsage     float64
	Disks        []DiskMetric
	Uptime       string
	LoadAverage  string
	TopProcesses []string
}

type CPUTicks struct {
	User    uint64 `json:"user"`
	Nice    uint64 `json:"nice"`
	Sys     uint64 `json:"sys"`
	Idle    uint64 `json:"idle"`
	Iowait  uint64 `json:"iowait"`
	Irq     uint64 `json:"irq"`
	Softirq uint64 `json:"softirq"`
	Steal   uint64 `json:"steal"`
}

func (t *CPUTicks) Total() uint64 {
	return t.User + t.Nice + t.Sys + t.Idle + t.Iowait + t.Irq + t.Softirq + t.Steal
}

func (t *CPUTicks) IdleTicks() uint64 {
	return t.Idle + t.Iowait
}

//go:embed assets/probe.sh
var probeScript string

// JSON stream messages
type streamMsg struct {
	Type      string `json:"type"`
	Uptime    uint64 `json:"uptime"`
	Load      string `json:"load"`
	Count     int    `json:"count"`
	Total     uint64 `json:"total"`
	Available uint64 `json:"available"`
	Mount     string `json:"mount"`
	Used      uint64 `json:"used"`
	PID       int    `json:"pid"`
	Name      string `json:"name"`
	State     string `json:"state"`
	Utime     uint64 `json:"utime"`
	Stime     uint64 `json:"stime"`
	RssKB     uint64 `json:"rss_kb"`
	CPUTicks
}

type procTick struct {
	Utime uint64
	Stime uint64
	Name  string
	State string
	RssKB uint64
}

type MetricsCollector struct {
	client     *Client
	decoder    *json.Decoder
	stream     io.ReadCloser
	lastTicks  *CPUTicks
	lastProcs  map[int]procTick
	coresCount int
	SortBy     string // "cpu", "mem"
	SortAsc    bool
	cancel     context.CancelFunc
}

func NewMetricsCollector(c *Client) *MetricsCollector {
	return &MetricsCollector{
		client:    c,
		lastProcs: make(map[int]procTick),
		SortBy:    "cpu",
		SortAsc:   false,
	}
}

func (mc *MetricsCollector) Start(ctx context.Context) error {
	derivedCtx, cancel := context.WithCancel(ctx)
	mc.cancel = cancel

	// 发送探针前，先探测系统平台
	osName, err := mc.client.RunWithoutLogin(derivedCtx, "uname -s")
	if err != nil {
		cancel()
		return fmt.Errorf("failed to detect OS platform: %w", err)
	}
	osName = strings.TrimSpace(osName)
	if osName != "Linux" {
		cancel()
		return fmt.Errorf("dashboard monitoring is not supported on %s (Linux only)", osName)
	}

	stream, err := mc.client.RunStream(derivedCtx, probeScript)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to start stream: %w", err)
	}
	mc.stream = stream
	mc.decoder = json.NewDecoder(stream)
	return nil
}

func (mc *MetricsCollector) Close() {
	if mc.cancel != nil {
		mc.cancel()
	}
	if mc.stream != nil {
		_ = mc.stream.Close()
	}
}

func (mc *MetricsCollector) NextFrame(ctx context.Context) (*SystemMetrics, error) {
	if mc.decoder == nil {
		return nil, fmt.Errorf("collector not started")
	}

	metrics := &SystemMetrics{}
	metrics.Cores = mc.coresCount
	currentProcs := make(map[int]procTick)
	var currentTicks *CPUTicks

	for {
		var msg streamMsg
		errCh := make(chan error, 1)
		go func() {
			errCh <- mc.decoder.Decode(&msg)
		}()

		select {
		case err := <-errCh:
			if err != nil {
				return nil, fmt.Errorf("decode stream message failed: %w", err)
			}
		case <-ctx.Done():
			// Close stream to unblock Decode and prevent internal desync
			mc.Close()
			return nil, ctx.Err()
		}

		switch msg.Type {
		case "sys":
			metrics.Uptime = formatUptime(msg.Uptime)
		case "load":
			metrics.LoadAverage = msg.Load
		case "cores":
			mc.coresCount = msg.Count
		case "cpu":
			currentTicks = &msg.CPUTicks
			mc.processCPU(currentTicks, metrics)
		case "mem":
			mc.processMem(&msg, metrics)
		case "disk":
			mc.processDisk(&msg, metrics)
		case "proc":
			currentProcs[msg.PID] = procTick{
				Utime: msg.Utime,
				Stime: msg.Stime,
				Name:  msg.Name,
				State: msg.State,
				RssKB: msg.RssKB,
			}
		case "eof":
			mc.processEOF(metrics, currentProcs, currentTicks)
			return metrics, nil
		}
	}
}

func (mc *MetricsCollector) processCPU(currentTicks *CPUTicks, metrics *SystemMetrics) {
	metrics.CPUUsage = 0
	if mc.lastTicks != nil && currentTicks != nil {
		totalDelta := float64(currentTicks.Total() - mc.lastTicks.Total())
		idleDelta := float64(currentTicks.IdleTicks() - mc.lastTicks.IdleTicks())
		if totalDelta > 0 {
			metrics.CPUUsage = 100.0 * (totalDelta - idleDelta) / totalDelta
		}
	}
}

func (mc *MetricsCollector) processMem(msg *streamMsg, metrics *SystemMetrics) {
	metrics.MemTotal = msg.Total / 1024
	if msg.Total >= msg.Available {
		metrics.MemUsed = (msg.Total - msg.Available) / 1024
	}
	if metrics.MemTotal > 0 {
		metrics.MemUsage = float64(metrics.MemUsed) / float64(metrics.MemTotal) * 100.0
	}
}

func (mc *MetricsCollector) processDisk(msg *streamMsg, metrics *SystemMetrics) {
	usage := 0.0
	if msg.Total > 0 {
		usage = float64(msg.Used) / float64(msg.Total) * 100.0
	}
	metrics.Disks = append(metrics.Disks, DiskMetric{
		MountPoint: msg.Mount,
		Total:      msg.Total / 1024,
		Used:       msg.Used / 1024,
		Usage:      usage,
	})
}

type procUsage struct {
	pid   int
	name  string
	state string
	rssMB float64
	cpu   float64
}

func (mc *MetricsCollector) processEOF(metrics *SystemMetrics, currentProcs map[int]procTick, currentTicks *CPUTicks) {
	var usages []procUsage

	var totalDelta uint64
	if mc.lastTicks != nil && currentTicks != nil {
		totalDelta = currentTicks.Total() - mc.lastTicks.Total()
	}

	for pid, curr := range currentProcs {
		cpuPercent := 0.0
		if prev, ok := mc.lastProcs[pid]; ok && totalDelta > 0 {
			procDelta := (curr.Utime + curr.Stime) - (prev.Utime + prev.Stime)
			cores := float64(mc.coresCount)
			if cores == 0 {
				cores = 1
			}
			// 100.0 * (process delta / total delta) * cores
			cpuPercent = 100.0 * float64(procDelta) / float64(totalDelta) * cores
		}
		usages = append(usages, procUsage{
			pid:   pid,
			name:  curr.Name,
			state: curr.State,
			rssMB: float64(curr.RssKB) / 1024.0,
			cpu:   cpuPercent,
		})
	}

	// Sort based on preferences
	sort.Slice(usages, func(i, j int) bool {
		var less bool
		if mc.SortBy == "mem" {
			if usages[i].rssMB == usages[j].rssMB {
				less = usages[i].cpu < usages[j].cpu
			} else {
				less = usages[i].rssMB < usages[j].rssMB
			}
		} else {
			// default: cpu
			if usages[i].cpu == usages[j].cpu {
				less = usages[i].rssMB < usages[j].rssMB
			} else {
				less = usages[i].cpu < usages[j].cpu
			}
		}

		if mc.SortAsc {
			return less
		}
		return !less
	})

	// Pick top 10
	limit := 10
	if len(usages) < 10 {
		limit = len(usages)
	}
	for i := 0; i < limit; i++ {
		u := usages[i]
		metrics.TopProcesses = append(metrics.TopProcesses, fmt.Sprintf("%-6d %-4s %5.1fMB %5.1f%% %s", u.pid, u.state, u.rssMB, u.cpu, u.name))
	}

	mc.lastProcs = currentProcs
	mc.lastTicks = currentTicks
}
func formatUptime(uptime uint64) string {
	days := uptime / 86400
	hours := (uptime % 86400) / 3600
	mins := (uptime % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%d days, %02d:%02d", days, hours, mins)
	}
	return fmt.Sprintf("%02d:%02d", hours, mins)
}
