package engine

import (
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
)

// Engine 是会话决策引擎，所有数据均在内存中。
//
// 并发设计：不用全局锁串行化操作。策略表、用户表、会话表各有短临界区的
// 读写锁；每个会话、每个用户有自己的锁。全局版本号在每次 SetPolicy/SetUser
// 生效后递增；会话记录自己追平到的版本。变更操作在返回前同步重评受影响的
// 会话；与变更并发建立的会话通过追平循环赶上最新版本。
type Engine struct {
	policiesMu sync.RWMutex
	policies   map[string]*Policy
	sorted     []*Policy // 生效策略，按优先级降序、ID 升序；写时整体替换

	usersMu sync.RWMutex
	users   map[string]*userState

	sessionsMu sync.RWMutex
	sessions   map[uint64]*sessionState

	version atomic.Uint64
	nextID  atomic.Uint64
	sink    Sink
}

type userState struct {
	mu    sync.RWMutex
	attrs UserAttrs

	sessMu   sync.Mutex
	sessions map[uint64]*sessionState
}

type sessionState struct {
	mu         sync.Mutex
	id         uint64
	userID     string
	authMethod string
	decision   Decision
	version    uint64
	revoked    bool
}

// NewEngine 构造一个引擎，sink 接收所有决策变化事件。
func NewEngine(sink Sink) *Engine {
	return &Engine{
		policies: make(map[string]*Policy),
		users:    make(map[string]*userState),
		sessions: make(map[uint64]*sessionState),
		sink:     sink,
	}
}

// SetPolicy 新增、替换或停用一条策略。返回时所有存活会话已反映本次变更。
func (e *Engine) SetPolicy(p Policy) error {
	if err := validatePolicy(&p); err != nil {
		return err
	}
	e.policiesMu.Lock()
	if p.Disabled {
		delete(e.policies, p.ID)
	} else {
		if _, exists := e.policies[p.ID]; !exists && len(e.policies) >= MaxActivePolicies {
			e.policiesMu.Unlock()
			return ErrTooManyPolicies
		}
		cp := p
		cp.Ports = append([]uint16(nil), p.Ports...)
		cp.Cond.AuthMethods = append([]string(nil), p.Cond.AuthMethods...)
		e.policies[p.ID] = &cp
	}
	e.rebuildSortedLocked()
	e.policiesMu.Unlock()

	e.version.Add(1)
	e.reevaluateAll()
	return nil
}

// SetUser 新建或修改用户属性。返回时该用户的所有存活会话已反映本次变更。
// 开销只与该用户的会话数成正比。
func (e *Engine) SetUser(id string, attrs UserAttrs) {
	u := e.getOrCreateUser(id)
	u.mu.Lock()
	u.attrs = attrs
	u.mu.Unlock()

	e.version.Add(1)

	u.sessMu.Lock()
	ss := make([]*sessionState, 0, len(u.sessions))
	for _, s := range u.sessions {
		ss = append(ss, s)
	}
	u.sessMu.Unlock()
	for _, s := range ss {
		e.reevaluate(s)
	}
}

// OpenSession 建立会话，返回会话 ID 与初始决策。
// 不同用户的 OpenSession 可并行求值。
func (e *Engine) OpenSession(userID, authMethod string) (uint64, Decision) {
	u := e.getOrCreateUser(userID)
	v := e.version.Load()
	d := e.compute(userID, authMethod)

	id := e.nextID.Add(1)
	s := &sessionState{
		id:         id,
		userID:     userID,
		authMethod: authMethod,
		decision:   d,
		version:    v,
	}
	e.sessionsMu.Lock()
	e.sessions[id] = s
	e.sessionsMu.Unlock()
	u.sessMu.Lock()
	u.sessions[id] = s
	u.sessMu.Unlock()

	// 注册窗口内可能有变更已经生效但未覆盖到本会话，追平到最新版本。
	// 追平产生的事件以初始决策 d 为链首，OpenSession 仍返回 d。
	for {
		cur := e.version.Load()
		s.mu.Lock()
		stale := s.version < cur
		s.mu.Unlock()
		if !stale {
			break
		}
		e.reevaluate(s)
	}
	return id, d
}

// RevokeSession 撤销会话；返回后该会话查不到，sink 也不再收到它的事件。
func (e *Engine) RevokeSession(id uint64) bool {
	e.sessionsMu.Lock()
	s, ok := e.sessions[id]
	if ok {
		delete(e.sessions, id)
	}
	e.sessionsMu.Unlock()
	if !ok {
		return false
	}
	if u := e.getUser(s.userID); u != nil {
		u.sessMu.Lock()
		delete(u.sessions, id)
		u.sessMu.Unlock()
	}
	s.mu.Lock()
	s.revoked = true
	s.mu.Unlock()
	return true
}

// Decision 查询会话当前决策。只锁定该会话并惰性追平，
// 不会等待正在进行的全量重评结束。
func (e *Engine) Decision(sessionID uint64) (Decision, error) {
	e.sessionsMu.RLock()
	s, ok := e.sessions[sessionID]
	e.sessionsMu.RUnlock()
	if !ok {
		return Quarantine, ErrSessionNotFound
	}
	e.reevaluate(s)
	s.mu.Lock()
	d := s.decision
	s.mu.Unlock()
	return d, nil
}

// compute 用当前策略快照和用户属性快照求值。
func (e *Engine) compute(userID, authMethod string) Decision {
	e.policiesMu.RLock()
	sorted := e.sorted
	e.policiesMu.RUnlock()

	var attrs UserAttrs
	if u := e.getUser(userID); u != nil {
		u.mu.RLock()
		attrs = u.attrs
		u.mu.RUnlock()
	}
	return evalDecision(sorted, attrs, authMethod)
}

// reevaluate 在会话锁内把单个会话追平到调用时的版本；
// 决策实际变化时投递一条事件。已撤销会话直接跳过。
func (e *Engine) reevaluate(s *sessionState) {
	v := e.version.Load()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || s.version >= v {
		return
	}
	d := e.compute(s.userID, s.authMethod)
	if !equalDecision(d, s.decision) {
		ev := Event{SessionID: s.id, Old: s.decision, New: d}
		s.decision = d
		if e.sink != nil {
			e.sink(ev)
		}
	}
	s.version = v
}

// reevaluateAll 同步重评全部存活会话，用 worker 池并行，返回前完成。
func (e *Engine) reevaluateAll() {
	e.sessionsMu.RLock()
	ss := make([]*sessionState, 0, len(e.sessions))
	for _, s := range e.sessions {
		ss = append(ss, s)
	}
	e.sessionsMu.RUnlock()

	workers := runtime.NumCPU()
	if len(ss) < workers {
		workers = len(ss)
	}
	if workers == 0 {
		return
	}
	var wg sync.WaitGroup
	var idx atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(idx.Add(1)) - 1
				if i >= len(ss) {
					return
				}
				e.reevaluate(ss[i])
			}
		}()
	}
	wg.Wait()
}

func (e *Engine) getUser(id string) *userState {
	e.usersMu.RLock()
	u := e.users[id]
	e.usersMu.RUnlock()
	return u
}

func (e *Engine) getOrCreateUser(id string) *userState {
	if u := e.getUser(id); u != nil {
		return u
	}
	e.usersMu.Lock()
	defer e.usersMu.Unlock()
	if u, ok := e.users[id]; ok {
		return u
	}
	u := &userState{sessions: make(map[uint64]*sessionState)}
	e.users[id] = u
	return u
}

// rebuildSortedLocked 重建有序生效策略列表；调用时需持有 policiesMu 写锁。
func (e *Engine) rebuildSortedLocked() {
	sorted := make([]*Policy, 0, len(e.policies))
	for _, p := range e.policies {
		sorted = append(sorted, p)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})
	e.sorted = sorted
}

func validatePolicy(p *Policy) error {
	if p.ID == "" || p.Priority < 1 || p.Priority > 1000 {
		return ErrInvalidPolicy
	}
	if !p.Disabled {
		if p.VLAN < 1 || p.VLAN > 4094 {
			return ErrInvalidPolicy
		}
		if c := p.Cond.Clearance; c != nil && (c.Min < 1 || c.Max > 5 || c.Min > c.Max) {
			return ErrInvalidPolicy
		}
	}
	return nil
}
