package engine_test

import (
	"fmt"
	"testing"

	"ztna/engine"
)

func collect() (*recorder, *engine.Engine) {
	rec := newRecorder()
	return rec, engine.NewEngine(rec.sink)
}

func TestBasicEval(t *testing.T) {
	rec, e := collect()

	// 无策略：隔离网段，无端口
	id, d := e.OpenSession("u1", "mfa")
	if !decEq(d, engine.Quarantine) {
		t.Fatalf("无策略时应为隔离网段, got %+v", d)
	}

	// 优先级高者胜出
	e.SetPolicy(engine.Policy{ID: "low", Priority: 10, VLAN: 100, Ports: []uint16{80}})
	e.SetPolicy(engine.Policy{ID: "high", Priority: 20, VLAN: 200, Ports: []uint16{443}})
	if got, _ := e.Decision(id); got.VLAN != 200 {
		t.Fatalf("优先级高者应胜出, got %+v", got)
	}

	// 优先级相同取 ID 字节序最小者
	e.SetPolicy(engine.Policy{ID: "aaa", Priority: 20, VLAN: 300, Ports: []uint16{1}})
	if got, _ := e.Decision(id); got.VLAN != 300 {
		t.Fatalf("同优先级应取 ID 最小者, got %+v", got)
	}

	// 条件不满足则跳过：role 不匹配
	e.SetPolicy(engine.Policy{ID: "zzz", Priority: 99, VLAN: 400, Cond: engine.Conditions{Role: strptr("admin")}})
	if got, _ := e.Decision(id); got.VLAN != 300 {
		t.Fatalf("role 不匹配的策略不应生效, got %+v", got)
	}
	e.SetUser("u1", engine.UserAttrs{Role: "admin", Clearance: 3})
	if got, _ := e.Decision(id); got.VLAN != 400 {
		t.Fatalf("SetUser 后 role 匹配应生效, got %+v", got)
	}

	// authMethod 属于集合
	e.SetPolicy(engine.Policy{ID: "auth", Priority: 100, VLAN: 500, Cond: engine.Conditions{AuthMethods: []string{"cert", "password"}}})
	if got, _ := e.Decision(id); got.VLAN != 400 {
		t.Fatalf("authMethod 不在集合中不应生效, got %+v", got)
	}

	// clearance 闭区间
	e.SetPolicy(engine.Policy{ID: "clr", Priority: 101, VLAN: 600, Cond: engine.Conditions{Clearance: &engine.ClearanceRange{Min: 3, Max: 5}}})
	if got, _ := e.Decision(id); got.VLAN != 600 {
		t.Fatalf("clearance=3 应落在 [3,5] 内, got %+v", got)
	}
	e.SetUser("u1", engine.UserAttrs{Role: "admin", Clearance: 2})
	if got, _ := e.Decision(id); got.VLAN != 400 {
		t.Fatalf("clearance=2 应落在 [3,5] 外, got %+v", got)
	}

	// 停用策略
	if err := e.SetPolicy(engine.Policy{ID: "clr", Priority: 1, VLAN: 1, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.Decision(id); got.VLAN != 400 {
		t.Fatalf("停用后不应再生效, got %+v", got)
	}

	// 事件链：Old/New 连续
	prev := d
	for _, re := range rec.events(id) {
		if !decEq(re.ev.Old, prev) {
			t.Fatalf("事件链断裂: Old=%+v 应为 %+v", re.ev.Old, prev)
		}
		prev = re.ev.New
	}
	if got, _ := e.Decision(id); !decEq(got, prev) {
		t.Fatalf("链尾 %+v != Decision %+v", prev, got)
	}

	// 撤销：查不到，且之后的变更不再产生该会话的事件
	nBefore := len(rec.events(id))
	if !e.RevokeSession(id) {
		t.Fatal("RevokeSession 应返回 true")
	}
	if _, err := e.Decision(id); err != engine.ErrSessionNotFound {
		t.Fatalf("撤销后应查不到, got %v", err)
	}
	e.SetUser("u1", engine.UserAttrs{Role: "ops", Clearance: 5})
	e.SetPolicy(engine.Policy{ID: "after", Priority: 1000, VLAN: 900})
	if n := len(rec.events(id)); n != nBefore {
		t.Fatalf("撤销后不应再收到事件, 之前 %d 条, 现在 %d 条", nBefore, n)
	}
}

func TestMaxPolicies(t *testing.T) {
	_, e := collect()
	for i := 0; i < engine.MaxActivePolicies; i++ {
		p := engine.Policy{ID: fmt.Sprintf("p%04d", i), Priority: 1, VLAN: 1}
		if err := e.SetPolicy(p); err != nil {
			t.Fatalf("第 %d 条策略应成功: %v", i, err)
		}
	}
	if err := e.SetPolicy(engine.Policy{ID: "overflow", Priority: 1, VLAN: 1}); err != engine.ErrTooManyPolicies {
		t.Fatalf("超出上限应返回 ErrTooManyPolicies, got %v", err)
	}
	// 替换已有策略不受上限影响
	if err := e.SetPolicy(engine.Policy{ID: "p0000", Priority: 2, VLAN: 2}); err != nil {
		t.Fatalf("替换已有策略应成功: %v", err)
	}
	// 停用后可再新增
	if err := e.SetPolicy(engine.Policy{ID: "p0001", Priority: 1, VLAN: 1, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPolicy(engine.Policy{ID: "overflow", Priority: 1, VLAN: 1}); err != nil {
		t.Fatalf("停用一条后应可新增: %v", err)
	}
}

func TestNoEventWhenUnchanged(t *testing.T) {
	rec, e := collect()
	e.SetUser("u1", engine.UserAttrs{Role: "dev", Clearance: 1})
	id, _ := e.OpenSession("u1", "mfa")
	// 修改不影响决策的属性/策略：不得投递事件
	e.SetUser("u1", engine.UserAttrs{Role: "dev", Clearance: 2})
	e.SetPolicy(engine.Policy{ID: "nomatch", Priority: 1, VLAN: 10, Cond: engine.Conditions{Role: strptr("admin")}})
	if n := len(rec.events(id)); n != 0 {
		t.Fatalf("决策未变化不应投递事件, got %d 条", n)
	}
}
