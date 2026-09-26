// Package engine 实现零信任网络准入的会话决策引擎。
// 数据只保存在内存中，不做持久化。
package engine

import "errors"

// 引擎层面可能返回的错误。
var (
	// ErrTooManyPolicies 表示生效策略数已达上限 500。
	ErrTooManyPolicies = errors.New("engine: too many active policies (max 500)")
	// ErrSessionNotFound 表示会话不存在或已被撤销。
	ErrSessionNotFound = errors.New("engine: session not found")
	// ErrInvalidPolicy 表示策略字段非法。
	ErrInvalidPolicy = errors.New("engine: invalid policy")
)

// MaxActivePolicies 是生效策略数上限。
const MaxActivePolicies = 500

// ClearanceRange 表示 clearance 的闭区间 [Min, Max]，取值 1-5。
type ClearanceRange struct {
	Min int
	Max int
}

// Conditions 是策略的可选条件集合；未设置（零值）的条件视为满足。
type Conditions struct {
	Role        *string         // 精确匹配；nil 表示不限制
	Department  *string         // 精确匹配；nil 表示不限制
	DeviceType  *string         // 精确匹配；nil 表示不限制
	AuthMethods []string        // authMethod 属于该集合；空表示不限制
	Clearance   *ClearanceRange // 闭区间；nil 表示不限制
}

// Policy 是一条准入策略。
type Policy struct {
	ID       string
	Priority int // 1-1000，越大越优先
	Cond     Conditions
	VLAN     uint16   // 1-4094
	Ports    []uint16 // 允许的端口列表
	Disabled bool     // true 时 SetPolicy 表示停用该策略
}

// UserAttrs 是用户属性，随时可被 SetUser 修改。
type UserAttrs struct {
	Role       string
	Department string
	DeviceType string
	Clearance  int // 1-5
}

// Decision 是一次准入决策的结果。
type Decision struct {
	VLAN  uint16
	Ports []uint16
}

// Quarantine 是隔离网段决策：无任何策略匹配时的结果。
var Quarantine = Decision{VLAN: 0, Ports: nil}

// Event 在某会话的决策实际变化时投递给 sink。
type Event struct {
	SessionID uint64
	Old       Decision
	New       Decision
}

// Sink 接收决策变化事件。可能被并发调用；实现需快速且不得回调引擎。
type Sink func(Event)
