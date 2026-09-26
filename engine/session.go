package engine

import (
	"strconv"
	"sync"
)

// session 一个存活会话的内部状态。attrs/dec/version/revoked 均受 mu 保护。
type session struct {
	id         string
	userID     string
	authMethod string

	mu      sync.Mutex
	attrs   UserAttrs // 用户属性快照，由 SetUser 在 userState.mu 下同步更新
	dec     Decision
	version uint64 // 最近一次求值所用的策略快照版本
	revoked bool
}

// userState 一个用户的内部状态。
type userState struct {
	mu       sync.Mutex
	attrs    UserAttrs
	sessions map[string]*session
}

// OpenSession 建立会话，返回会话 ID 与初始决策。不同用户的建会话可并行求值。
func (e *Engine) OpenSession(userID, authMethod string) (string, Decision) {
	u := e.userStateOf(userID)
	u.mu.Lock()
	defer u.mu.Unlock()

	id := strconv.FormatUint(e.nextID.Add(1), 10)
	s := &session{id: id, userID: userID, authMethod: authMethod, attrs: u.attrs}
	s.mu.Lock()
	defer s.mu.Unlock()

	// 先注册再求值：保证并发的 SetPolicy 全量重评一定能看到本会话；
	// 重评若先到，会阻塞在 s.mu 上直到初始决策就绪，随后按版本号再评。
	e.sessions.Store(id, s)
	u.sessions[id] = s

	e.policyMu.RLock()
	s.dec = evaluate(e.policies, &s.attrs, s.authMethod)
	s.version = e.version
	e.policyMu.RUnlock()
	return id, s.dec
}

// RevokeSession 撤销会话。返回后该会话查不到，sink 也不再收到它的任何事件，
// 正在进行的重评不会让它复活。
func (e *Engine) RevokeSession(id string) {
	v, ok := e.sessions.LoadAndDelete(id)
	if !ok {
		return
	}
	s := v.(*session)
	if u, ok := e.users.Load(s.userID); ok {
		us := u.(*userState)
		us.mu.Lock()
		delete(us.sessions, id)
		us.mu.Unlock()
	}
	s.mu.Lock()
	s.revoked = true
	s.mu.Unlock()
}

// Decision 查询会话当前决策。
func (e *Engine) Decision(sessionID string) (Decision, error) {
	v, ok := e.sessions.Load(sessionID)
	if !ok {
		return Quarantine, ErrSessionNotFound
	}
	s := v.(*session)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return Quarantine, ErrSessionNotFound
	}
	d := Decision{VLAN: s.dec.VLAN, Ports: append([]int(nil), s.dec.Ports...)}
	return d, nil
}
