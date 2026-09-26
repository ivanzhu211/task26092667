package engine

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countSink 记录每个会话的事件流与计数。
type countSink struct {
	mu     sync.Mutex
	events map[string][]Event
	total  int
}

func newCountSink() *countSink { return &countSink{events: make(map[string][]Event)} }

func (c *countSink) OnDecisionChange(e Event) {
	c.mu.Lock()
	c.events[e.SessionID] = append(c.events[e.SessionID], e)
	c.total++
	c.mu.Unlock()
}

func (c *countSink) forSession(id string) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.events[id]...)
}

// sessionRec 测试侧记录的会话信息。
type sessionRec struct {
	user           string
	auth           string
	initial        Decision
	revoked        bool
	eventsAtRevoke int
}

// registry 并发安全的会话登记表。
type registry struct {
	mu   sync.Mutex
	recs map[string]*sessionRec
	ids  []string
}

func newRegistry() *registry { return &registry{recs: make(map[string]*sessionRec)} }

func (r *registry) add(id string, rec *sessionRec) {
	r.mu.Lock()
	r.recs[id] = rec
	r.ids = append(r.ids, id)
	r.mu.Unlock()
}

func (r *registry) markRevoked(id string, eventsAtRevoke int) {
	r.mu.Lock()
	if rec, ok := r.recs[id]; ok {
		rec.revoked = true
		rec.eventsAtRevoke = eventsAtRevoke
	}
	r.mu.Unlock()
}

func (r *registry) randomID(rnd *rand.Rand) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ids) == 0 {
		return "", false
	}
	return r.ids[rnd.Intn(len(r.ids))], true
}

func (r *registry) snapshot() map[string]*sessionRec {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*sessionRec, len(r.recs))
	for id, rec := range r.recs {
		cp := *rec
		out[id] = &cp
	}
	return out
}

// recompute 用引擎当前状态重新求值（测试与引擎同包，直接读内部状态）。
func recompute(e *Engine, userID, authMethod string) Decision {
	u := e.userStateOf(userID)
	u.mu.Lock()
	attrs := u.attrs
	u.mu.Unlock()
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	return evaluate(e.policies, &attrs, authMethod)
}

// 压力测试用的策略集：若干广匹配策略，优先级会被反复对调，足以改变胜出者。
func stressPolicies() []Policy {
	return []Policy{
		{ID: "sp-any", Enabled: true, Priority: 100, VLAN: 10, Ports: []int{80}},
		{ID: "sp-clear-lo", Enabled: true, Priority: 900, MaxClearance: 2, VLAN: 20, Ports: []int{80, 443}},
		{ID: "sp-clear-hi", Enabled: true, Priority: 150, MinClearance: 4, VLAN: 30, Ports: []int{22}},
		{ID: "sp-auth", Enabled: true, Priority: 500, AuthMethods: []string{"totp", "webauthn"}, VLAN: 40, Ports: []int{443}},
		{ID: "sp-role", Enabled: true, Priority: 700, Role: "ops", VLAN: 50, Ports: []int{22, 443}},
	}
}

// flipPriorities 返回同一批策略但优先级重新洗牌后的版本。
func flipPriorities(base []Policy, rnd *rand.Rand) []Policy {
	prios := []int{100, 150, 500, 700, 900}
	rnd.Shuffle(len(prios), func(i, j int) { prios[i], prios[j] = prios[j], prios[i] })
	out := make([]Policy, len(base))
	for i, p := range base {
		p.Priority = prios[i%len(prios)]
		out[i] = p
	}
	return out
}

func TestStressMixed(t *testing.T) {
	sink := newCountSink()
	e := New(sink)
	reg := newRegistry()

	const numUsers = 12
	users := make([]string, numUsers)
	for i := range users {
		users[i] = fmt.Sprintf("user-%d", i)
		e.SetUser(users[i], UserAttrs{Role: "ops", Department: "eng", DeviceType: "laptop", Clearance: 1})
	}
	base := stressPolicies()
	for _, p := range base {
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
	}
	auths := []string{"password", "totp", "webauthn"}

	var stop atomic.Bool
	var wg sync.WaitGroup

	// 建会话
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for i := 0; i < 250 && !stop.Load(); i++ {
				u := users[rnd.Intn(len(users))]
				a := auths[rnd.Intn(len(auths))]
				id, d := e.OpenSession(u, a)
				reg.add(id, &sessionRec{user: u, auth: a, initial: d})
			}
		}(int64(g) + 1)
	}
	// 撤销会话
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				if id, ok := reg.randomID(rnd); ok {
					e.RevokeSession(id)
					reg.markRevoked(id, len(sink.forSession(id)))
				}
				time.Sleep(time.Millisecond)
			}
		}(int64(g) + 100)
	}
	// 反复修改用户 clearance
	for g := 0; g < 3; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				u := users[rnd.Intn(len(users))]
				e.SetUser(u, UserAttrs{
					Role:       "ops",
					Department: "eng",
					DeviceType: "laptop",
					Clearance:  1 + rnd.Intn(5),
				})
			}
		}(int64(g) + 200)
	}
	// 反复调整优先级
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for !stop.Load() {
				for _, p := range flipPriorities(base, rnd) {
					if err := e.SetPolicy(p); err != nil {
						t.Errorf("SetPolicy: %v", err)
						return
					}
				}
			}
		}(int64(g) + 300)
	}

	time.Sleep(3 * time.Second)
	stop.Store(true)
	wg.Wait()

	// 逐会话校验性质 1、3、4。
	recs := reg.snapshot()
	if len(recs) == 0 {
		t.Fatal("no sessions recorded")
	}
	for id, rec := range recs {
		evs := sink.forSession(id)
		prev := rec.initial
		for _, ev := range evs {
			if !equalDecision(ev.Old, prev) {
				t.Fatalf("session %s: chain broken Old=%+v prev=%+v", id, ev.Old, prev)
			}
			prev = ev.New
		}
		if rec.revoked {
			if _, err := e.Decision(id); err != ErrSessionNotFound {
				t.Fatalf("session %s: revoked but Decision err=%v", id, err)
			}
			if len(evs) != rec.eventsAtRevoke {
				t.Fatalf("session %s: events after revoke: at=%d now=%d", id, rec.eventsAtRevoke, len(evs))
			}
			continue
		}
		got, err := e.Decision(id)
		if err != nil {
			t.Fatalf("session %s: %v", id, err)
		}
		if !equalDecision(got, prev) {
			t.Fatalf("session %s: Decision=%+v != last event New=%+v", id, got, prev)
		}
		if want := recompute(e, rec.user, rec.auth); !equalDecision(got, want) {
			t.Fatalf("session %s: convergence Decision=%+v want=%+v", id, got, want)
		}
	}
	t.Logf("checked %d sessions, %d events", len(recs), sink.total)
}

func TestStressSetPolicyVisibility(t *testing.T) {
	sink := newCountSink()
	e := New(sink)
	reg := newRegistry()

	const numUsers = 8
	users := make([]string, numUsers)
	for i := range users {
		users[i] = fmt.Sprintf("u-%d", i)
		e.SetUser(users[i], UserAttrs{Role: "ops", Clearance: 3})
	}
	base := stressPolicies()
	for _, p := range base {
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy: %v", err)
		}
	}
	auths := []string{"password", "totp"}

	var stop atomic.Bool
	var wg sync.WaitGroup
	// 大量并发建会话
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(seed))
			for i := 0; i < 200 && !stop.Load(); i++ {
				u := users[rnd.Intn(len(users))]
				a := auths[rnd.Intn(len(auths))]
				id, d := e.OpenSession(u, a)
				reg.add(id, &sessionRec{user: u, auth: a, initial: d})
			}
		}(int64(g) + 1)
	}

	// 单个 goroutine 顺序 SetPolicy；每次返回后立即校验所有存活会话已反映。
	rnd := rand.New(rand.NewSource(42))
	for iter := 0; iter < 30; iter++ {
		for _, p := range flipPriorities(base, rnd) {
			if err := e.SetPolicy(p); err != nil {
				t.Fatalf("SetPolicy: %v", err)
			}
			for id, rec := range reg.snapshot() {
				got, err := e.Decision(id)
				if err != nil {
					t.Fatalf("iter %d session %s: %v", iter, id, err)
				}
				if want := recompute(e, rec.user, rec.auth); !equalDecision(got, want) {
					t.Fatalf("iter %d session %s: Decision=%+v want=%+v", iter, id, got, want)
				}
			}
		}
	}
	stop.Store(true)
	wg.Wait()
}
