package engine

import (
	"fmt"
	"sync"
	"testing"
)

// recSink 记录事件的测试 sink。
type recSink struct {
	mu     sync.Mutex
	events []Event
}

func (r *recSink) OnDecisionChange(e Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recSink) forSession(id string) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for _, e := range r.events {
		if e.SessionID == id {
			out = append(out, e)
		}
	}
	return out
}

func mustDecision(t *testing.T, e *Engine, id string) Decision {
	t.Helper()
	d, err := e.Decision(id)
	if err != nil {
		t.Fatalf("Decision(%s): %v", id, err)
	}
	return d
}

func TestEvalRules(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	e.SetUser("u1", UserAttrs{Role: "admin", Department: "eng", DeviceType: "laptop", Clearance: 3})

	policies := []Policy{
		{ID: "p-low", Enabled: true, Priority: 10, VLAN: 100, Ports: []int{80}},
		{ID: "p-high", Enabled: true, Priority: 900, Role: "admin", VLAN: 200, Ports: []int{443}},
		{ID: "p-role-miss", Enabled: true, Priority: 1000, Role: "root", VLAN: 300},
		{ID: "p-auth", Enabled: true, Priority: 950, AuthMethods: []string{"webauthn"}, VLAN: 400},
		{ID: "p-clearance", Enabled: true, Priority: 940, MinClearance: 4, MaxClearance: 5, VLAN: 500},
		{ID: "p-dept", Enabled: true, Priority: 930, Department: "sales", VLAN: 600},
	}
	for _, p := range policies {
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy(%s): %v", p.ID, err)
		}
	}

	// 匹配中优先级最高的是 p-high（p-auth/p-clearance/p-dept/p-role-miss 条件不满足）。
	_, d := e.OpenSession("u1", "password")
	if d.VLAN != 200 {
		t.Fatalf("want VLAN 200, got %+v", d)
	}

	// authMethod 属于集合时 p-auth 胜出。
	_, d = e.OpenSession("u1", "webauthn")
	if d.VLAN != 400 {
		t.Fatalf("want VLAN 400, got %+v", d)
	}

	// clearance 落入区间时 p-clearance 胜出于 password 会话。
	e.SetUser("u1", UserAttrs{Role: "admin", Clearance: 5})
	_, d = e.OpenSession("u1", "password")
	if d.VLAN != 500 {
		t.Fatalf("want VLAN 500, got %+v", d)
	}
}

func TestTieBreakByID(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	e.SetUser("u", UserAttrs{})
	e.SetPolicy(Policy{ID: "b", Enabled: true, Priority: 100, VLAN: 1})
	e.SetPolicy(Policy{ID: "a", Enabled: true, Priority: 100, VLAN: 2})
	_, d := e.OpenSession("u", "m")
	if d.VLAN != 2 {
		t.Fatalf("tie-break: want ID 'a' (VLAN 2), got %+v", d)
	}
}

func TestQuarantineFallback(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	e.SetUser("u", UserAttrs{Role: "x"})
	e.SetPolicy(Policy{ID: "p", Enabled: true, Priority: 1, Role: "y", VLAN: 10})
	id, d := e.OpenSession("u", "m")
	if !equalDecision(d, Quarantine) {
		t.Fatalf("want quarantine, got %+v", d)
	}
	// 改为可匹配后应收到一条事件并脱离隔离。
	e.SetPolicy(Policy{ID: "p", Enabled: true, Priority: 1, VLAN: 10, Ports: []int{22}})
	if got := mustDecision(t, e, id); got.VLAN != 10 {
		t.Fatalf("want VLAN 10, got %+v", got)
	}
	evs := sink.forSession(id)
	if len(evs) != 1 || !equalDecision(evs[0].Old, Quarantine) || evs[0].New.VLAN != 10 {
		t.Fatalf("bad events: %+v", evs)
	}
}

func TestEventChainingAndNoSpurious(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	e.SetUser("u", UserAttrs{Clearance: 1})
	e.SetPolicy(Policy{ID: "p1", Enabled: true, Priority: 100, VLAN: 1})
	e.SetPolicy(Policy{ID: "p2", Enabled: true, Priority: 200, MaxClearance: 2, VLAN: 2})

	id, d0 := e.OpenSession("u", "m")
	if d0.VLAN != 2 {
		t.Fatalf("want VLAN 2, got %+v", d0)
	}
	// 无实际变化：重设相同策略不应产生事件。
	e.SetPolicy(Policy{ID: "p1", Enabled: true, Priority: 100, VLAN: 1})
	if n := len(sink.forSession(id)); n != 0 {
		t.Fatalf("spurious events: %d", n)
	}
	// clearance 提升使 p2 失配 -> 事件 1。
	e.SetUser("u", UserAttrs{Clearance: 3})
	// 调整优先级使 p1 超过... p2 已失配，决策应已是 VLAN 1。
	if got := mustDecision(t, e, id); got.VLAN != 1 {
		t.Fatalf("want VLAN 1, got %+v", got)
	}
	// 停用 p1 -> 隔离，事件 2。
	e.SetPolicy(Policy{ID: "p1", Enabled: false})
	if got := mustDecision(t, e, id); !equalDecision(got, Quarantine) {
		t.Fatalf("want quarantine, got %+v", got)
	}
	evs := sink.forSession(id)
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d: %+v", len(evs), evs)
	}
	prev := d0
	for _, ev := range evs {
		if !equalDecision(ev.Old, prev) {
			t.Fatalf("chain broken: Old=%+v prev=%+v", ev.Old, prev)
		}
		prev = ev.New
	}
	if got := mustDecision(t, e, id); !equalDecision(got, prev) {
		t.Fatalf("final mismatch: Decision=%+v lastNew=%+v", got, prev)
	}
}

func TestRevoke(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	e.SetUser("u", UserAttrs{})
	e.SetPolicy(Policy{ID: "p", Enabled: true, Priority: 1, VLAN: 1})
	id, _ := e.OpenSession("u", "m")
	e.RevokeSession(id)
	if _, err := e.Decision(id); err != ErrSessionNotFound {
		t.Fatalf("want ErrSessionNotFound, got %v", err)
	}
	n := len(sink.forSession(id))
	// 撤销后的变更不得再产生该会话的事件。
	e.SetPolicy(Policy{ID: "p", Enabled: true, Priority: 1, VLAN: 9})
	e.SetUser("u", UserAttrs{Role: "r"})
	if got := len(sink.forSession(id)); got != n {
		t.Fatalf("events after revoke: %d -> %d", n, got)
	}
	// 重复撤销安全。
	e.RevokeSession(id)
}

func TestPolicyLimitsAndValidation(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	for i := 0; i < MaxPolicies; i++ {
		p := Policy{ID: fmt.Sprintf("p%d", i), Enabled: true, Priority: 1, VLAN: 1}
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("SetPolicy %d: %v", i, err)
		}
	}
	if err := e.SetPolicy(Policy{ID: "overflow", Enabled: true, Priority: 1, VLAN: 1}); err != ErrTooManyPolicies {
		t.Fatalf("want ErrTooManyPolicies, got %v", err)
	}
	// 替换既有 ID 不受上限影响。
	if err := e.SetPolicy(Policy{ID: "p0", Enabled: true, Priority: 2, VLAN: 2}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	// 停用后可再新增。
	e.SetPolicy(Policy{ID: "p1", Enabled: false})
	if err := e.SetPolicy(Policy{ID: "overflow", Enabled: true, Priority: 1, VLAN: 1}); err != nil {
		t.Fatalf("after disable: %v", err)
	}
	bad := []Policy{
		{ID: "", Enabled: true, Priority: 1, VLAN: 1},
		{ID: "x", Enabled: true, Priority: 0, VLAN: 1},
		{ID: "x", Enabled: true, Priority: 1001, VLAN: 1},
		{ID: "x", Enabled: true, Priority: 1, VLAN: 0},
		{ID: "x", Enabled: true, Priority: 1, VLAN: 4095},
		{ID: "x", Enabled: true, Priority: 1, VLAN: 1, MinClearance: 6},
		{ID: "x", Enabled: true, Priority: 1, VLAN: 1, MinClearance: 4, MaxClearance: 2},
	}
	for _, p := range bad {
		if err := e.SetPolicy(p); err != ErrInvalidPolicy {
			t.Fatalf("want ErrInvalidPolicy for %+v, got %v", p, err)
		}
	}
}

func TestSetUserScoped(t *testing.T) {
	sink := &recSink{}
	e := New(sink)
	e.SetUser("a", UserAttrs{Role: "r1"})
	e.SetUser("b", UserAttrs{Role: "r2"})
	e.SetPolicy(Policy{ID: "p", Enabled: true, Priority: 1, Role: "r1", VLAN: 1})
	idA, _ := e.OpenSession("a", "m")
	idB, _ := e.OpenSession("b", "m")
	// 修改 b 不影响 a。
	e.SetUser("b", UserAttrs{Role: "r1"})
	if got := mustDecision(t, e, idA); got.VLAN != 1 {
		t.Fatalf("a changed unexpectedly: %+v", got)
	}
	if got := mustDecision(t, e, idB); got.VLAN != 1 {
		t.Fatalf("b want VLAN 1, got %+v", got)
	}
	if n := len(sink.forSession(idA)); n != 0 {
		t.Fatalf("a got %d spurious events", n)
	}
	if n := len(sink.forSession(idB)); n != 1 {
		t.Fatalf("b want 1 event, got %d", n)
	}
}
