// Package engine 实现零信任网络准入的会话决策引擎（纯内存库）。
package engine

// UserAttrs 用户属性，可随时通过 SetUser 修改。
type UserAttrs struct {
	Role       string
	Department string
	DeviceType string
	Clearance  int // 1-5
}

// Policy 一条策略。条件的零值表示该条件未设置（视为满足）。
type Policy struct {
	ID       string
	Priority int // 1-1000

	// 可选条件（零值 = 未设置）
	Role         string   // 精确匹配
	Department   string   // 精确匹配
	DeviceType   string   // 精确匹配
	AuthMethods  []string // authMethod 属于该集合
	MinClearance int      // 闭区间下界，0 = 未设置
	MaxClearance int      // 闭区间上界，0 = 未设置

	// 结果
	VLAN  int   // 1-4094
	Ports []int // 端口列表

	// Enabled 为 false 时 SetPolicy 表示停用（从生效集中移除）该 ID 的策略。
	Enabled bool
}

// Decision 一次准入决策的结果。
type Decision struct {
	VLAN  int   // 0 表示隔离网段
	Ports []int // 隔离网段时为空
}

// Quarantine 隔离网段决策（无端口）。
var Quarantine = Decision{VLAN: 0, Ports: nil}

// Event 决策变化事件。
type Event struct {
	SessionID string
	Old       Decision
	New       Decision
}

// Sink 事件接收方。可能被并发调用；要求本身快速且不回调引擎。
type Sink interface {
	OnDecisionChange(Event)
}

// SinkFunc 函数适配器。
type SinkFunc func(Event)

// OnDecisionChange 实现 Sink。
func (f SinkFunc) OnDecisionChange(e Event) { f(e) }
