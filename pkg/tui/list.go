package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type nodeItem struct {
	id       string
	name     string
	address  string
	user     string
	tags     string
	selected bool
}

// Title 只返回纯文本，样式的上色逻辑全部交给 Delegate 处理，以防止乱码。
func (i *nodeItem) Title() string {
	if i.selected {
		return "[x] " + i.name
	}
	return "[ ] " + i.name
}

func (i *nodeItem) Description() string {
	return fmt.Sprintf("%s@%s - [%s]", i.user, i.address, i.tags)
}

func (i *nodeItem) FilterValue() string {
	return i.id + " " + i.name + " " + i.address + " " + i.user + " " + i.tags
}

// checkedDelegate 自定义委托器，支持勾选项的高亮显示
type checkedDelegate struct {
	list.DefaultDelegate
}

func (d checkedDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	ni, ok := item.(*nodeItem)
	if !ok {
		d.DefaultDelegate.Render(w, m, index, item)
		return
	}

	// 保存原始样式
	origSelectedTitle := d.Styles.SelectedTitle
	origSelectedDesc := d.Styles.SelectedDesc
	origNormalTitle := d.Styles.NormalTitle
	origNormalDesc := d.Styles.NormalDesc

	// 如果被勾选，修改样式添加绿色左边框
	if ni.selected {
		checkedBorder := lipgloss.NormalBorder()
		checkedColor := lipgloss.Color("2") // 绿色

		// 修改 Normal 样式（非光标行）
		d.Styles.NormalTitle = d.Styles.NormalTitle.
			Border(checkedBorder, false, false, false, true).
			BorderForeground(checkedColor).
			Padding(0, 0, 0, 1)
		d.Styles.NormalDesc = d.Styles.NormalDesc.
			Border(checkedBorder, false, false, false, true).
			BorderForeground(checkedColor).
			Padding(0, 0, 0, 1)

		// 修改 Selected 样式（光标行）- 同时显示选中色和勾选色
		d.Styles.SelectedTitle = d.Styles.SelectedTitle.
			Border(checkedBorder, false, false, false, true).
			BorderForeground(checkedColor).
			Padding(0, 0, 0, 1)
		d.Styles.SelectedDesc = d.Styles.SelectedDesc.
			Border(checkedBorder, false, false, false, true).
			BorderForeground(checkedColor).
			Padding(0, 0, 0, 1)
	}

	d.DefaultDelegate.Render(w, m, index, item)

	// 恢复原始样式
	d.Styles.SelectedTitle = origSelectedTitle
	d.Styles.SelectedDesc = origSelectedDesc
	d.Styles.NormalTitle = origNormalTitle
	d.Styles.NormalDesc = origNormalDesc
}

func newListModel(provider config.ConfigProvider) list.Model {
	nodes := provider.ListNodes()
	var items []list.Item

	for id, node := range nodes {
		identity, _ := provider.GetIdentity(id)
		host, _ := provider.GetHost(id)

		name := id
		if len(node.Alias) > 0 {
			name = strings.Join(node.Alias, ", ")
		}

		items = append(items, &nodeItem{
			id:      id,
			name:    name,
			address: host.Address,
			user:    identity.User,
			tags:    strings.Join(node.Tags, ","),
		})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].(*nodeItem).name < items[j].(*nodeItem).name
	})

	// 获取默认委派器并进行自定义配置
	delegate := checkedDelegate{DefaultDelegate: list.NewDefaultDelegate()}
	// 设置光标所在行（Selected）的高亮样式
	delegate.Styles.SelectedTitle = lipgloss.NewStyle().
		Foreground(selectedColor).
		Bold(true).
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(selectedColor).
		Padding(0, 0, 0, 1)

	// 描述部分设置更暗的颜色
	delegate.Styles.SelectedDesc = delegate.Styles.SelectedTitle.
		Foreground(lipgloss.Color("8")).
		Bold(false)

	l := list.New(items, delegate, 0, 0)
	l.Title = i18n.T("tui_list_title")
	l.SetShowStatusBar(true)
	l.SetFilteringEnabled(true)

	// 自定义过滤逻辑，实现子字符串匹配
	l.Filter = func(term string, targets []string) []list.Rank {
		ranks := make([]list.Rank, 0)
		for i, target := range targets {
			index := strings.Index(strings.ToLower(target), strings.ToLower(term))
			if index >= 0 {
				matchedIndexes := make([]int, len(term))
				for j := 0; j < len(term); j++ {
					matchedIndexes[j] = index + j
				}
				ranks = append(ranks, list.Rank{
					Index:          i,
					MatchedIndexes: matchedIndexes,
				})
			}
		}
		return ranks
	}

	// 添加快捷键帮助
	l.AdditionalShortHelpKeys = func() []key.Binding {
		return []key.Binding{
			key.NewBinding(key.WithKeys("space"), key.WithHelp("space", i18n.T("tui_help_space"))),
			key.NewBinding(key.WithKeys("a"), key.WithHelp("a", i18n.T("tui_help_all"))),
			key.NewBinding(key.WithKeys("v"), key.WithHelp("v", i18n.T("tui_help_invert"))),
			key.NewBinding(key.WithKeys("d"), key.WithHelp("d", i18n.T("tui_help_delete"))),
			key.NewBinding(key.WithKeys("e"), key.WithHelp("e", i18n.T("tui_help_edit"))),
			key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "monitor")),
			key.NewBinding(key.WithKeys("l"), key.WithHelp("l", i18n.T("tui_help_log"))),
			key.NewBinding(key.WithKeys("n"), key.WithHelp("n", i18n.T("tui_help_new"))),
			key.NewBinding(key.WithKeys("g"), key.WithHelp("g", i18n.T("tui_help_tag"))),
		}
	}

	return l
}

func (m *Model) updateList(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := appStyle.GetFrameSize()
		// 如果有状态消息，需要为底部的 "\n\n" + status 留出 3 行空间
		if m.status != "" {
			v += 3
		}
		m.list.SetSize(msg.Width-h, msg.Height-v)
		return *m, nil

	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return *m, cmd
}

func (m *Model) handleKeyMsg(msg tea.KeyMsg) (Model, tea.Cmd) {
	if m.list.SettingFilter() {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return *m, cmd
	}

	// 处理删除确认状态
	if m.handleDeletePending(msg) {
		return *m, nil
	}

	// 处理快捷键
	if handler, ok := m.getKeyHandler(msg.String()); ok {
		return handler()
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return *m, cmd
}

// handleDeletePending 处理删除确认状态，返回 true 表示已处理
func (m *Model) handleDeletePending(msg tea.KeyMsg) bool {
	if !m.deletePending {
		return false
	}
	if msg.String() == "d" {
		return false
	}
	m.deletePending = false
	m.status = ""
	*m, _ = m.updateList(m.lastSize)
	return msg.String() == "esc"
}

// getKeyHandler 获取按键处理函数
func (m *Model) getKeyHandler(key string) (func() (Model, tea.Cmd), bool) {
	handlers := map[string]func() (Model, tea.Cmd){
		"enter": m.handleEnter,
		" ":     m.handleSpace,
		"a":     m.handleSelectAll,
		"v":     m.handleInvertSelection,
		"d":     m.handleDelete,
		"n":     m.handleNew,
		"e":     m.handleEdit,
		"m":     m.handleMonitor,
		"l":     m.handleLogSelect,
		"g":     m.handleTagAction,
	}

	if h, ok := handlers[key]; ok {
		return h, true
	}

	if key == "q" || key == "ctrl+c" {
		return func() (Model, tea.Cmd) { return *m, tea.Quit }, true
	}

	if key == "esc" && m.list.FilterState() == list.Unfiltered {
		return func() (Model, tea.Cmd) { return *m, tea.Quit }, true
	}

	return nil, false
}

func (m *Model) handleEnter() (Model, tea.Cmd) {
	selected := m.list.SelectedItem()
	if selected != nil {
		nodeID := selected.(*nodeItem).id
		return *m, runSSH(nodeID)
	}
	return *m, nil
}

func (m *Model) handleSpace() (Model, tea.Cmd) {
	selectedItem, ok := m.list.SelectedItem().(*nodeItem)
	if ok {
		// 直接修改指针指向的值
		selectedItem.selected = !selectedItem.selected
		// 获取全量列表并重新设置，以触发列表内部的刷新
		items := m.list.Items()
		cmd := m.list.SetItems(items)
		return *m, cmd
	}
	return *m, nil
}

func (m *Model) handleSelectAll() (Model, tea.Cmd) {
	// 获取当前可见的项（如果是过滤状态，只包含过滤结果）
	visibleItems := m.list.VisibleItems()

	// 创建一个 map 来快速查找哪些项需要被选中
	toSelect := make(map[string]bool)
	for _, item := range visibleItems {
		if ni, ok := item.(*nodeItem); ok {
			toSelect[ni.id] = true
		}
	}

	// 遍历所有项，更新选中状态
	all := m.list.Items()
	for _, item := range all {
		ni := item.(*nodeItem)
		if toSelect[ni.id] {
			ni.selected = true
		}
	}
	cmd := m.list.SetItems(all)
	return *m, cmd
}

func (m *Model) handleInvertSelection() (Model, tea.Cmd) {
	// 获取可见项 ID 集合
	visibleItems := m.list.VisibleItems()
	toInvert := make(map[string]bool)
	for _, item := range visibleItems {
		if ni, ok := item.(*nodeItem); ok {
			toInvert[ni.id] = true
		}
	}

	all := m.list.Items()
	for _, item := range all {
		ni := item.(*nodeItem)
		if toInvert[ni.id] {
			ni.selected = !ni.selected
		}
	}
	cmd := m.list.SetItems(all)
	return *m, cmd
}

func (m *Model) handleDelete() (Model, tea.Cmd) {
	if !m.deletePending {
		m.deletePending = true
		m.status = errorStyle.Render(i18n.T("tui_confirm_delete"))
		// 刷新列表大小以容纳状态提示
		*m, _ = m.updateList(m.lastSize)
		return *m, nil
	}

	m.deletePending = false

	// 只删除当前可见（过滤后）且被勾选的项
	visibleItems := m.list.VisibleItems()
	visibleMap := make(map[string]bool)
	for _, item := range visibleItems {
		if ni, ok := item.(*nodeItem); ok {
			visibleMap[ni.id] = true
		}
	}

	var toDelete []string
	all := m.list.Items()
	for _, i := range all {
		if ni, ok := i.(*nodeItem); ok && ni.selected && visibleMap[ni.id] {
			toDelete = append(toDelete, ni.id)
		}
	}

	// 如果没有批量选中的，则删除当前悬停的这一项
	if len(toDelete) == 0 {
		if sel, ok := m.list.SelectedItem().(*nodeItem); ok {
			toDelete = append(toDelete, sel.id)
		}
	}

	if len(toDelete) > 0 {
		for _, id := range toDelete {
			m.provider.DeleteNode(id)
		}
		_ = m.configStore.Save(m.provider.GetConfig())
		// 设置状态消息
		m.status = successStyle.Render(i18n.Tf("tui_status_deleted", map[string]any{"Count": len(toDelete)}))
		// 刷新列表模型
		m.list = newListModel(m.provider)
		*m, _ = m.updateList(m.lastSize)
	}
	return *m, nil
}

func (m *Model) handleNew() (Model, tea.Cmd) {
	var cmd tea.Cmd
	*m, cmd = m.initForm("")
	m.state = viewForm
	return *m, cmd
}

func (m *Model) handleEdit() (Model, tea.Cmd) {
	selected := m.list.SelectedItem()
	if selected != nil {
		nodeID := selected.(*nodeItem).id
		var cmd tea.Cmd
		*m, cmd = m.initForm(nodeID)
		m.state = viewForm
		return *m, cmd
	}
	return *m, nil
}

type monitorConnectedMsg struct {
	nodeID string
	client *ssh.Client
	err    error
}

func (m *Model) handleMonitor() (Model, tea.Cmd) {
	selected := m.list.SelectedItem()
	if selected == nil {
		return *m, nil
	}
	nodeID := selected.(*nodeItem).id
	m.status = i18n.Tf("tui_monitor_connecting", map[string]any{"Node": nodeID})

	return *m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client, err := m.connector.Connect(ctx, nodeID)
		return monitorConnectedMsg{nodeID: nodeID, client: client, err: err}
	}
}

func (m *Model) handleLogSelect() (Model, tea.Cmd) {
	selected := m.list.SelectedItem()
	if selected == nil {
		return *m, nil
	}
	nodeID := selected.(*nodeItem).id
	m.status = i18n.Tf("tui_log_connecting", map[string]any{"Node": nodeID})

	return *m, func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client, err := m.connector.Connect(ctx, nodeID)
		return logScannerConnectedMsg{nodeID: nodeID, client: client, err: err}
	}
}

func (m *Model) handleTagAction() (Model, tea.Cmd) {
	// 检查是否有勾选的节点
	visibleItems := m.list.VisibleItems()
	visibleMap := make(map[string]bool)
	for _, item := range visibleItems {
		if ni, ok := item.(*nodeItem); ok {
			visibleMap[ni.id] = true
		}
	}

	var selectedNodes []string
	all := m.list.Items()
	for _, i := range all {
		if ni, ok := i.(*nodeItem); ok && ni.selected && visibleMap[ni.id] {
			selectedNodes = append(selectedNodes, ni.id)
		}
	}

	// 如果没有勾选的节点，提示用户
	if len(selectedNodes) == 0 {
		m.status = errorStyle.Render(i18n.T("tui_no_selection"))
		*m, _ = m.updateList(m.lastSize)
		return *m, nil
	}

	// 初始化标签选择表单
	*m = m.initTagSelectForm()
	m.state = viewTagSelect
	return *m, nil
}

type sshFinishedMsg struct{ err error }

// TODO(refactor): TUI 框架的渲染边界与环境变量扩散
// 目前通过注入 XOPS_CLI_SSH_FROM_TUI 环境变量，让 ssh 子进程在连接失败时阻塞等待回车。这可能导致环境变量被孙进程意外继承。
// 遵循 BubbleTea 最佳实践，未来重构时应让子进程直接返回 exit error，由父进程 (TUI) 捕获后在 UI 层面渲染失败提示弹窗，而不是依赖子进程接管终端进行阻塞。
func runSSH(nodeID string) tea.Cmd {
	c := os.Args[0]
	cmd := exec.Command(c, "ssh", nodeID)
	cmd.Env = append(os.Environ(), "XOPS_CLI_SSH_FROM_TUI=true")
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		return sshFinishedMsg{err}
	})
}
