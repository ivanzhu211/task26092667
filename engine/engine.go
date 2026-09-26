package engine

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
)

// MaxPolicies 生效策略条数上限。
const MaxPolicies = 500

// 错误集合。
var (
	ErrInvalidPolicy   = errors.New("engine: invalid policy")
	ErrTooManyPolicies = errors.New("engine: too many active policies")
	ErrSessionNotFound = errors.New("engine: session not found")
)

// Engine 会话决策引擎。所有数据仅在内存中。
//
// 并发设计：
//   - 策略集与 version 构成一致快照，由 policyMu 保护；读取方只加读锁。
//   - 每个会话一把 mu，决策变更与事件投递都在会话锁内完成，保证事件链式连续。
//   - 每个用户一把 userState.mu，SetUser 只遍历该用户的会话。
//   - SetPolicy 的全量重评只逐个短持会话锁，不阻塞 OpenSession/Decision/SetUser。
//   - 锁序：userState.mu -> session.mu -> policyMu(读)。policyMu 永远最后获取。
type Engine struct {
	sink Sink

	mutMu sync.Mutex // 仅串行化多次 SetPolicy 的「更新+全量重评」

	policyMu sync.RWMutex // 保护 policies 与 version，二者构成一致快照
	policies map[string]*Policy
	version  uint64

	sessions sync.Map // sessionID -> *session
	users    sync.Map // userID -> *userState

	nextID atomic.Uint64 // 会话 ID 计数器
}

// New 构造引擎，sink 不能为 nil。
func New(sink Sink) *Engine {
	if sink == nil {
		panic("engine: nil sink")
	}
	return &Engine{
		sink:     sink,
		policies: make(map[string]*Policy),
	}
}

// validate 校验策略字段合法性。
func validate(p *Policy) error {
	if p.ID == "" {
		return ErrInvalidPolicy
	}
	if !p.Enabled {
		return nil // 停用只需合法 ID
	}
	if p.Priority < 1 || p.Priority > 1000 {
		return ErrInvalidPolicy
	}
	if p.VLAN < 1 || p.VLAN > 4094 {
		return ErrInvalidPolicy
	}
	for _, c := range []int{p.MinClearance, p.MaxClearance} {
		if c != 0 && (c < 1 || c > 5) {
			return ErrInvalidPolicy
		}
	}
	if p.MinClearance != 0 && p.MaxClearance != 0 && p.MinClearance > p.MaxClearance {
		return ErrInvalidPolicy
	}
	return nil
}

// SetPolicy 新增、替换或停用一条策略。返回时所有存活会话（包括并发建立的）
// 均已反映本次变更及此前已返回的全部变更。
func (e *Engine) SetPolicy(p Policy) error {
	if err := validate(&p); err != nil {
		return err
	}
	e.mutMu.Lock()
	defer e.mutMu.Unlock()

	e.policyMu.Lock()
	if p.Enabled {
		if _, exists := e.policies[p.ID]; !exists && len(e.policies) >= MaxPolicies {
			e.policyMu.Unlock()
			return ErrTooManyPolicies
		}
		cp := p
		cp.AuthMethods = slices.Clone(p.AuthMethods)
		cp.Ports = slices.Clone(p.Ports)
		e.policies[p.ID] = &cp
	} else {
		delete(e.policies, p.ID)
	}
	e.version++
	v := e.version
	e.policyMu.Unlock()

	// 全量重评：逐个短持会话锁，不阻塞其他操作。
	e.sessions.Range(func(_, val any) bool {
		s := val.(*session)
		s.mu.Lock()
		if !s.revoked && s.version < v {
			e.reevaluateLocked(s)
		}
		s.mu.Unlock()
		return true
	})
	return nil
}

// SetUser 新建或修改用户属性。开销只与该用户的会话数成正比。
func (e *Engine) SetUser(id string, attrs UserAttrs) {
	u := e.userStateOf(id)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.attrs = attrs
	for _, s := range u.sessions {
		s.mu.Lock()
		if !s.revoked {
			s.attrs = attrs
			e.reevaluateLocked(s)
		}
		s.mu.Unlock()
	}
}

// userState 返回该用户的内部状态，不存在则创建。
func (e *Engine) userStateOf(id string) *userState {
	if u, ok := e.users.Load(id); ok {
		return u.(*userState)
	}
	u, _ := e.users.LoadOrStore(id, &userState{sessions: make(map[string]*session)})
	return u.(*userState)
}

// reevaluateLocked 用当前策略快照重评会话。调用方必须持有 s.mu 且会话未撤销。
// 决策实际变化时投递事件；事件在会话锁内投递，保证同一会话的事件有序且链式连续。
func (e *Engine) reevaluateLocked(s *session) {
	e.policyMu.RLock()
	d := evaluate(e.policies, &s.attrs, s.authMethod)
	v := e.version
	e.policyMu.RUnlock()
	if !equalDecision(d, s.dec) {
		ev := Event{SessionID: s.id, Old: s.dec, New: d}
		s.dec = d
		e.sink.OnDecisionChange(ev)
	}
	s.version = v
}
