# batch50-py-safety-b-09

## 题面

网络设备管理面上了 confirmed-commit 之后，变更窗口连续出事：运维提交完配置没来得及确认，定时器到期把变更回滚了，但候选版本号却往回跳；另一个会话拿着过期的 persist-id 又确认了一次，回滚时间被意外延长；还有一次两台终端同时提交，后到的直接把前一个未确认提交覆盖掉，锁的归属也对不上。值班记录里还提到，回滚之后候选配置没有回到上一个已确认版本，后续提交基于了错误的基线。范围是 gsb/batch50-py-safety-b-09 的 netconf_commit_guard.py，类 ConfirmedCommitGuard，负责未确认提交的回滚定时器、persist-id 的一次性核销、跨会话接管与数据存储锁归属。

公开接口：ConfirmedCommitGuard(*, default_timeout=60)；commit(session_id, candidate, *, datastore="running", timeout=None, persist_id=None, now=None)；confirm(session_id, *, datastore="running", commit_id=None, persist_id=None, now=None)；rollback(session_id=None, *, datastore="running", commit_id=None, now=None)；persist(session_id, *, datastore="running", persist_id=None)；adopt(session_id, persist_id, *, datastore="running")；lock_datastore(session_id, datastore="running")；unlock_datastore(session_id, datastore="running")；close_session(session_id, *, now=None)；expire(now)；pending_for(datastore="running")；version_for(datastore="running")；config_for(datastore="running")；snapshot()、restore(state)、stats()。拒绝抛 NetconfError(code, detail)。

故障与边界：①commit 应用候选配置、版本号加一、启动回滚定时器，commit_id 从 1 递增，ticket 记录 commit_id、datastore、session_id、version、expires_at 与 persist_id。②confirm 必须在到期前到达，成功后取消回滚；超时后 expire 恢复提交前内容并把版本号再加一，计入回滚统计，confirm 与 rollback 返回操作后的版本号，expire 返回回滚个数，rollback 可提前手工触发；回滚只恢复提交前的内容，不删除期间其它会话的锁状态。③同一数据存储同时只允许一个未确认提交，第二个 commit 报 NETCONF_COMMIT_IN_PROGRESS；不同数据存储互不影响；进行中的提交对其它会话只可见摘要，不能读取候选内容。④未带 persist 的提交只能由原会话确认，其它会话确认报 NETCONF_WRONG_SESSION；带 persist-id 的提交允许其它会话凭 id 确认。⑤确认来自另一会话但 persist-id 不匹配时必须报 NETCONF_PERSIST_MISMATCH，不能因为定时器还没到就接受；同一 persist-id 被第二次确认只能报错，不能延长回滚时间。⑥未带 persist 的会话在定时器到期前断开，close_session 要立即回滚，不能等定时器走完；带 persist 的提交保留到到期，可被 adopt 接管。⑦adopt 只接受匹配的 persist-id，未知 id 报 NETCONF_UNKNOWN_PERSIST，接管后原会话不再拥有该提交，接管不重置到期时间，剩余时间照旧计算。⑧persist 为当前未确认提交生成或绑定 persist-id，非属主调用报 NETCONF_WRONG_SESSION。⑨数据存储锁被他人持有时 commit 与 lock 都要报 NETCONF_LOCK_HELD；非属主 unlock 报 NETCONF_NOT_OWNER，同一属主重复加锁按幂等处理，lock_denied 统计加锁或提交被锁拒绝的次数；锁不随提交结束自动释放，必须显式解锁或会话关闭时回收。⑩候选配置必须是字符串键、标量值的字典，非法结构报 NETCONF_INVALID_CANDIDATE 且配置与版本不动；timeout 非正整数报 NETCONF_INVALID_REQUEST。⑪未知 commit_id 报 NETCONF_UNKNOWN_COMMIT，待确认提交保持不变；config_for 与 pending_for 返回副本，调用方修改不影响内部状态。⑫快照含 version、stores、pendings、stats 四个顶层键并深拷贝，恢复后定时器按剩余时间继续，锁属主、提交编号与 persist-id 都不能丢；非法结构报 NETCONF_SNAPSHOT_INVALID 且原状态不变。

硬约束：同一数据存储的提交、确认、回滚必须串行，不能出现两个未确认提交或版本号回退；定时器、候选配置与 persist-id 要持久化，重启按绝对到期时间继续；锁归属严格按会话判定。stats 返回 commits、confirms、rollbacks、expired、adopted、lock_denied。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: netconf_commit_guard
- typeName: ConfirmedCommitGuard
