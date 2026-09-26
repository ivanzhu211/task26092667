# task26092667

零信任网络准入会话决策引擎（Go 库，纯内存，无持久化）。代码在 `engine/` 包。

## API

- `New(sink)` 构造引擎；决策每次实际变化向 sink 投递 `{SessionID, Old, New}`。
- `SetPolicy(p)` 新增 / 替换 / 停用（`Enabled=false`）策略；生效策略上限 500 条。
- `SetUser(id, attrs)` 新建或修改用户属性。
- `OpenSession(userID, authMethod)` 建会话，返回会话 ID 与初始决策。
- `RevokeSession(id)` 撤销会话；`Decision(id)` 查询当前决策。

求值规则：未设置的条件视为满足；全部满足的策略中优先级（1–1000）最高者胜，
并列取 ID 字节序最小者；无匹配落入隔离网段（VLAN 0，无端口）。

## 并发设计

- 策略集与版本号构成一致快照（`policyMu` 读写锁），求值只加读锁。
- 每个会话一把锁：决策变更与事件投递都在会话锁内完成，保证事件链式连续。
- 每个用户一把锁：`SetUser` 只遍历该用户的会话，开销与其会话数成正比。
- `SetPolicy` 的版本递增在写锁内完成，随后全量重评逐个短持会话锁；
  `OpenSession` 先注册会话再读快照求值，保证并发的全量重评一定能看到它。
- 无后台 goroutine、无定期重扫；`SetPolicy`/`SetUser` 返回时状态已追平。

## 测试

```sh
go test ./...        # 单元测试
go test -race ./...  # 含压力测试：混合并发 + SetPolicy 即时生效校验
```
