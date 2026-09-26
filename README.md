# task26092667
## 零信任网络准入会话决策引擎

纯内存 Go 库，位于 `engine/` 包。

```go
rec := func(ev engine.Event) { /* 决策变化事件 */ }
e := engine.NewEngine(rec)

e.SetPolicy(engine.Policy{ID: "devs", Priority: 100, VLAN: 20, Ports: []uint16{443}})
e.SetUser("alice", engine.UserAttrs{Role: "dev", Clearance: 3})

id, d := e.OpenSession("alice", "mfa") // 建会话，返回初始决策
cur, _ := e.Decision(id)               // 查询当前决策
e.RevokeSession(id)                    // 撤销
```

- 求值：全部条件满足的策略中优先级最高者胜出，同优先级取 ID 最小者；都不匹配落入隔离网段（VLAN 0，无端口）。
- `SetPolicy` / `SetUser` 返回时，所有受影响存活会话的决策与事件已追平；会话决策每实际变化一次投递一条 `{SessionID, Old, New}` 事件。
- 生效策略上限 500 条（`ErrTooManyPolicies`）。
- 并发设计：无全局串行化锁；策略/用户/会话表各有短临界区读写锁，每会话、每用户独立锁，全局版本号 + 会话惰性追平。

测试：`go test ./engine/ -race`
