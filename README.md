# batch50-py-game-a-14

## 题面

昨晚跨服组队的状态全乱了：好友列表里已经掉线的人还亮着，队长等了十分钟也没等到系统提示；掉线重连后同一个人出现两条会话，队伍邀请发到了废弃的那条，进本判定直接失败；网关分片重启后一次性把整片玩家广播成下线，其中不少人还在重连宽限期内，公会频道被系统消息刷屏；还有客户端心跳风暴，把租约到期时间越推越远，实际掉线半小时后才被清理，挂机名单全是不准的；客服按账号查在线设备，拿到的列表里混着早就失效的会话。改动落在 gsb/batch50-py-game-a-14 的 presence_lease.py，类名 PresenceLease，负责租约授予、心跳续期、断线宽限、重连恢复与批量过期。运营要求好友列表、重连判重和分片恢复三条链路同时对齐，不能靠重启重新洗一遍在线状态。

公开接口：PresenceLease(*, ttl=60, grace=30, shard_count=4)；acquire(account, session_id, *, device, shard=0, now)、renew(session_id, *, now)、release(session_id, *, now)、resume(session_id, *, now)、expire_sweep(*, now)、shard_recover(shard, *, now)、sessions_on(account)、shard_sessions(shard)、session_of(session_id)、snapshot()、restore(state)、stats()。所有拒绝统一抛 PresenceError(code, detail)。

返回值约定：会话视图包含 session_id、account、device、status、expires_at、grace_until、preemptable、shard；下线事件包含 session_id、account、reason、lease_expired_at。

故障与边界：①账号、会话、设备任一为空或 shard 落在 0 到 shard_count-1 之外，抛 PRESENCE_INVALID；②同一 session_id 全局只能有一份，重复授予抛 PRESENCE_SESSION_EXISTS，下线后的 session_id 仍被占用，复用必须等清理；③同一账号在新设备登录，把该账号其他在线会话标记为可抢占；④心跳从当前时刻重新计算到期时间，状态不是 online 抛 PRESENCE_NOT_ONLINE，未知会话抛 PRESENCE_SESSION_UNKNOWN；⑤释放进入重连宽限，grace_until 等于当前时刻加 grace，原租约到期时间保留不动，宽限期内原会话不能被新设备顶掉；⑥宽限内 resume 沿用原 session_id，回到 online 并刷新到期时间；⑦超过宽限再 resume 抛 PRESENCE_GRACE_EXPIRED，会话状态保持 grace；⑧expire_sweep 先把在线且过期的会话转入宽限，再把宽限到期的会话转下线并产出下线事件，同一轮扫描里每个会话最多完成一次状态迁移；⑨下线事件按租约到期时间升序返回，同刻到期按 session_id 排序；⑩分片故障恢复后的批量过期必须按租约到期时间排序处理，仍在宽限期内的会话不广播下线，只标记为待确认状态；⑪同一账号的并发心跳只延长一次租约，剩余时间不得叠加；⑫stats 固定返回 acquired、renewed、released、resumed、swept、offline、online、grace 八项，统计随每次操作实时更新，快照必须深拷贝，非法结构抛 PRESENCE_SNAPSHOT_INVALID 且原状态不变。

硬约束：同一 session_id 的并发授予只能有一个成功，其余必须拿到 PRESENCE_SESSION_EXISTS；快照恢复后租约到期时间、宽限截止、可抢占标记、会话状态与全部统计必须和恢复前一致，且不与快照共享可变结构。

验收：`python3 -m pytest -q tests` 15 条全过；不得修改测试、跳过用例或针对固定输入写死；并发、分片恢复与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: presence_lease
- typeName: PresenceLease
