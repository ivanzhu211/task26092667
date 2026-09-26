package engine_test

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"

	"ztna/engine"
)

// ---------- 测试辅助 ----------

type recordedEvent struct {
	seq uint64
	ev  engine.Event
}

// recorder 记录全部事件，seq 为全局单调序号。
type recorder struct {
	mu        sync.Mutex
	seq       uint64
	bySession map[uint64][]recordedEvent
}

func newRecorder() *recorder {
	return &recorder{bySession: make(map[uint64][]recordedEvent)}
}

func (r *recorder) sink(ev engine.Event) {
	r.mu.Lock()
	r.seq++
	r.bySession[ev.SessionID] = append(r.bySession[ev.SessionID], recordedEvent{seq: r.seq, ev: ev})
	r.mu.Unlock()
}

func (r *recorder) currentSeq() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seq
}

func (r *recorder) events(id uint64) []recordedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedEvent(nil), r.bySession[id]...)
}

// lastDecision 返回该会话最后一条事件的 New；无事件时返回 initial。
func (r *recorder) lastDecision(id uint64, initial engine.Decision) engine.Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	evs := r.bySession[id]
	if len(evs) == 0 {
		return initial
	}
	return evs[len(evs)-1].ev.New
}

type sessionInfo struct {
	id         uint64
	userID     string
	authMethod string
	initial    engine.Decision
	revoked    bool
	revokeSeq  uint64
}

// tracker 跟踪测试侧看到的会话：全部会话 + 存活会话（支持 O(1) 随机选取）。
type tracker struct {
	mu       sync.Mutex
	all      map[uint64]*sessionInfo
	liveList []uint64
	liveIdx  map[uint64]int
}

func newTracker() *tracker {
	return &tracker{all: make(map[uint64]*sessionInfo), liveIdx: make(map[uint64]int)}
}

func (t *tracker) add(id uint64, userID, authMethod string, initial engine.Decision) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.all[id] = &sessionInfo{id: id, userID: userID, authMethod: authMethod, initial: initial}
	t.liveIdx[id] = len(t.liveList)
	t.liveList = append(t.liveList, id)
}

func (t *tracker) markRevoked(id uint64, seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	info := t.all[id]
	info.revoked = true
	info.revokeSeq = seq
	i, ok := t.liveIdx[id]
	if !ok {
		return
	}
	last := t.liveList[len(t.liveList)-1]
	t.liveList[i] = last
	t.liveIdx[last] = i
	t.liveList = t.liveList[:len(t.liveList)-1]
	delete(t.liveIdx, id)
}

func (t *tracker) randomLive(rng *rand.Rand) *sessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.liveList) == 0 {
		return nil
	}
	return t.all[t.liveList[rng.Intn(len(t.liveList))]]
}

func (t *tracker) liveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.liveList)
}

func (t *tracker) liveSnapshot() []*sessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*sessionInfo, 0, len(t.liveList))
	for _, id := range t.liveList {
		out = append(out, t.all[id])
	}
	return out
}

func (t *tracker) allSessions() []*sessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*sessionInfo, 0, len(t.all))
	for _, info := range t.all {
		out = append(out, info)
	}
	return out
}

// ---------- 独立模型（测试侧重新实现求值，用于交叉校验） ----------

func modelMatch(p *engine.Policy, a engine.UserAttrs, m string) bool {
	c := &p.Cond
	if c.Role != nil && *c.Role != a.Role {
		return false
	}
	if c.Department != nil && *c.Department != a.Department {
		return false
	}
	if c.DeviceType != nil && *c.DeviceType != a.DeviceType {
		return false
	}
	if len(c.AuthMethods) > 0 {
		ok := false
		for _, am := range c.AuthMethods {
			if am == m {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if c.Clearance != nil && (a.Clearance < c.Clearance.Min || a.Clearance > c.Clearance.Max) {
		return false
	}
	return true
}

func modelEval(pols map[string]engine.Policy, a engine.UserAttrs, m string) engine.Decision {
	var best *engine.Policy
	for _, p := range pols {
		p := p
		if !modelMatch(&p, a, m) {
			continue
		}
		if best == nil || p.Priority > best.Priority || (p.Priority == best.Priority && p.ID < best.ID) {
			best = &p
		}
	}
	if best == nil {
		return engine.Quarantine
	}
	return engine.Decision{VLAN: best.VLAN, Ports: append([]uint16(nil), best.Ports...)}
}

func decEq(a, b engine.Decision) bool {
	if a.VLAN != b.VLAN || len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		if a.Ports[i] != b.Ports[i] {
			return false
		}
	}
	return true
}

func strptr(s string) *string { return &s }

var (
	roles   = []string{"admin", "dev", "ops"}
	depts   = []string{"eng", "fin", "hr"}
	devices = []string{"laptop", "phone"}
	methods = []string{"password", "mfa", "cert"}
)

func mkPolicy(i int) engine.Policy {
	p := engine.Policy{
		ID:       fmt.Sprintf("p%02d", i),
		Priority: 1 + (i*67)%1000,
		VLAN:     uint16(10 + i),
		Ports:    []uint16{uint16(2000 + i), 443},
	}
	switch i % 4 {
	case 0:
		p.Cond.Role = strptr(roles[i%len(roles)])
	case 1:
		p.Cond.Department = strptr(depts[i%len(depts)])
		p.Cond.Clearance = &engine.ClearanceRange{Min: 1 + i%3, Max: 3 + i%3}
	case 2:
		p.Cond.AuthMethods = []string{methods[i%len(methods)], methods[(i+1)%len(methods)]}
	case 3:
		p.Cond.DeviceType = strptr(devices[i%len(devices)])
		p.Cond.Role = strptr(roles[(i+1)%len(roles)])
	}
	return p
}

// ---------- 阶段一：混沌压力测试 ----------

func TestStressChaos(t *testing.T) {
	rec := newRecorder()
	e := engine.NewEngine(rec.sink)

	var polMu sync.Mutex
	policies := make(map[string]engine.Policy)
	policyIDs := make([]string, 0, 15)
	for i := 0; i < 15; i++ {
		p := mkPolicy(i)
		policies[p.ID] = p
		policyIDs = append(policyIDs, p.ID)
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
	}

	const numUsers = 30
	users := make([]string, numUsers)
	var attrsMu sync.Mutex
	attrsMap := make(map[string]engine.UserAttrs)
	for i := 0; i < numUsers; i++ {
		u := fmt.Sprintf("u%02d", i)
		users[i] = u
		a := engine.UserAttrs{
			Role:       roles[i%len(roles)],
			Department: depts[i%len(depts)],
			DeviceType: devices[i%len(devices)],
			Clearance:  1 + i%5,
		}
		attrsMap[u] = a
		e.SetUser(u, a)
	}

	tr := newTracker()
	var stop atomic.Bool
	var wgFinite, wgAll sync.WaitGroup

	revokeOne := func(rng *rand.Rand) {
		victim := tr.randomLive(rng)
		if victim == nil {
			return
		}
		if e.RevokeSession(victim.id) {
			tr.markRevoked(victim.id, rec.currentSeq())
		}
	}

	// 建会话 goroutine
	for g := 0; g < 4; g++ {
		wgAll.Add(1)
		go func(seed int64) {
			defer wgAll.Done()
			rng := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				u := users[rng.Intn(len(users))]
				m := methods[rng.Intn(len(methods))]
				id, d := e.OpenSession(u, m)
				tr.add(id, u, m, d)
				if tr.liveCount() > 3000 {
					revokeOne(rng)
				}
			}
		}(int64(g)*7919 + 1)
	}
	// 撤销会话 goroutine
	for g := 0; g < 2; g++ {
		wgAll.Add(1)
		go func(seed int64) {
			defer wgAll.Done()
			rng := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				revokeOne(rng)
			}
		}(int64(g)*104729 + 7)
	}
	// 反复修改同一批用户的 clearance
	for g := 0; g < 4; g++ {
		wgFinite.Add(1)
		wgAll.Add(1)
		go func(seed int64) {
			defer wgFinite.Done()
			defer wgAll.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 200; i++ {
				u := users[rng.Intn(len(users))]
				attrsMu.Lock()
				a := attrsMap[u]
				a.Clearance = 1 + rng.Intn(5)
				attrsMap[u] = a
				e.SetUser(u, a)
				attrsMu.Unlock()
			}
		}(int64(g)*31337 + 3)
	}
	// 反复调整优先级，幅度足以改变胜出策略
	for g := 0; g < 2; g++ {
		wgFinite.Add(1)
		wgAll.Add(1)
		go func(seed int64) {
			defer wgFinite.Done()
			defer wgAll.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 150; i++ {
				polMu.Lock()
				p := policies[policyIDs[rng.Intn(len(policyIDs))]]
				p.Priority = 1 + rng.Intn(1000)
				policies[p.ID] = p
				if err := e.SetPolicy(p); err != nil {
					t.Errorf("SetPolicy: %v", err)
				}
				polMu.Unlock()
			}
		}(int64(g)*555557 + 5)
	}

	wgFinite.Wait()
	stop.Store(true)
	wgAll.Wait()

	// 最终状态快照
	attrsMu.Lock()
	finalAttrs := make(map[string]engine.UserAttrs, len(attrsMap))
	for k, v := range attrsMap {
		finalAttrs[k] = v
	}
	attrsMu.Unlock()
	polMu.Lock()
	finalPols := make(map[string]engine.Policy, len(policies))
	for k, v := range policies {
		finalPols[k] = v
	}
	polMu.Unlock()

	// 逐会话校验性质 1、3、4
	for _, info := range tr.allSessions() {
		evs := rec.events(info.id)
		prev := info.initial
		for _, re := range evs {
			if !decEq(re.ev.Old, prev) {
				t.Errorf("session %d: 事件链断裂, Old=%+v 应为 %+v", info.id, re.ev.Old, prev)
			}
			if re.ev.SessionID != info.id {
				t.Errorf("session %d: 事件 SessionID 错误 %d", info.id, re.ev.SessionID)
			}
			prev = re.ev.New
		}
		if info.revoked {
			// 性质 4：查不到，且撤销返回后无新事件
			if _, err := e.Decision(info.id); !errors.Is(err, engine.ErrSessionNotFound) {
				t.Errorf("session %d: 撤销后 Decision 应返回 ErrSessionNotFound, got %v", info.id, err)
			}
			for _, re := range evs {
				if re.seq > info.revokeSeq {
					t.Errorf("session %d: RevokeSession 返回后仍收到事件", info.id)
				}
			}
			continue
		}
		// 性质 1：链尾 == Decision 当前值
		d, err := e.Decision(info.id)
		if err != nil {
			t.Errorf("session %d: Decision: %v", info.id, err)
			continue
		}
		if !decEq(d, prev) {
			t.Errorf("session %d: 链尾 %+v != Decision %+v", info.id, prev, d)
		}
		// 性质 3：收敛到用当前策略集/属性/authMethod 重新求值的结果
		exp := modelEval(finalPols, finalAttrs[info.userID], info.authMethod)
		if !decEq(d, exp) {
			t.Errorf("session %d: 决策 %+v != 模型求值 %+v", info.id, d, exp)
		}
	}
}

// ---------- 阶段二：SetPolicy 返回即生效 ----------

func TestStressPolicyVisibility(t *testing.T) {
	rec := newRecorder()
	e := engine.NewEngine(rec.sink)

	const numUsers = 10
	users := make([]string, numUsers)
	attrsMap := make(map[string]engine.UserAttrs)
	for i := 0; i < numUsers; i++ {
		u := fmt.Sprintf("u%02d", i)
		users[i] = u
		a := engine.UserAttrs{
			Role:       roles[i%len(roles)],
			Department: depts[i%len(depts)],
			DeviceType: devices[i%len(devices)],
			Clearance:  1 + i%5,
		}
		attrsMap[u] = a
		e.SetUser(u, a)
	}

	var polMu sync.Mutex
	policies := make(map[string]engine.Policy)
	policyIDs := make([]string, 0, 15)
	for i := 0; i < 15; i++ {
		p := mkPolicy(i)
		policies[p.ID] = p
		policyIDs = append(policyIDs, p.ID)
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
	}

	tr := newTracker()
	var stop atomic.Bool
	var wg sync.WaitGroup
	// 并发大量 OpenSession（自我限流并随机撤销以控制规模）
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				u := users[rng.Intn(len(users))]
				m := methods[rng.Intn(len(methods))]
				id, d := e.OpenSession(u, m)
				tr.add(id, u, m, d)
				if tr.liveCount() > 2000 {
					victim := tr.randomLive(rng)
					if victim != nil && e.RevokeSession(victim.id) {
						tr.markRevoked(victim.id, rec.currentSeq())
					}
				}
			}
		}(int64(g)*2654435761 + 11)
	}

	// 只有一个 goroutine 调用 SetPolicy；每次返回后立即校验
	rng := rand.New(rand.NewSource(999))
	for i := 0; i < 100; i++ {
		polMu.Lock()
		p := policies[policyIDs[rng.Intn(len(policyIDs))]]
		p.Priority = 1 + rng.Intn(1000)
		policies[p.ID] = p
		cur := make(map[string]engine.Policy, len(policies))
		for k, v := range policies {
			cur[k] = v
		}
		polMu.Unlock()

		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}

		// SetPolicy 已返回：所有存活会话的当前决策（由事件链尾/初始决策刻画）
		// 必须已反映本次变更。
		for _, info := range tr.liveSnapshot() {
			exp := modelEval(cur, attrsMap[info.userID], info.authMethod)
			last := rec.lastDecision(info.id, info.initial)
			if decEq(last, exp) {
				continue
			}
			// 可能在快照后被并发撤销：撤销的会话不在性质 2 范围内
			if _, err := e.Decision(info.id); errors.Is(err, engine.ErrSessionNotFound) {
				continue
			}
			t.Errorf("第 %d 次 SetPolicy 返回后, session %d 决策 %+v 未反映变更, 期望 %+v",
				i, info.id, last, exp)
		}
	}
	stop.Store(true)
	wg.Wait()
}
