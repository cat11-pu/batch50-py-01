# batch50-py-safety-a-10

## 题面

账号恢复的自助流程上线两周，客服和风控各记了一本账：有人在等待期内把同一条恢复申请提交了四次，系统开了四个定时器，最早那个到期就放行，另外三个还在队列里排着；多通道确认只走到一个邮箱，短信通道没人点，工单却在等待期一到就交付了恢复凭据；凭据交付之后用户说没收到，客服在后台再点一次，屏幕上又原样显示了一遍同样的凭据；最离谱的是一起盗号申请，账号原持有人自己在等待期内登录了，系统只发了条通知，等待期照走照放。范围是 gsb/batch50-py-safety-a-10 的 recovery_hold_queue.py，类 RecoveryHoldQueue，负责等待期队列、多通道确认、异议撤销与一次性放行。

公开接口：RecoveryHoldQueue(*, hold_seconds=172800, confirmations_required=2, max_channels=3)；request(account_id, channels)、confirm_contact(hold_id, channel, token)、veto(hold_id, actor, reason)、release(hold_id)、status(hold_id)、due_holds()、sweep()、hold_view(hold_id)、snapshot()、restore(state)、stats()，时间参数统一 now 取整秒。拒绝一律抛 RecoveryError(code, detail)。request 返回 dict，键含 hold_id、account_id、channels、state、created_at、due_at、confirmations、required、tokens、merged；confirm_contact 返回 hold_id、channel、confirmed_at、confirmations、required、already；veto 返回 hold_id、state、vetoed_by、vetoed_at；release 返回 hold_id、state、released_at、credential；status 返回 hold_id、state、due_at、remaining、confirmations、required、channels；sweep 返回 released、expired、credentials；hold_view 与 request 同结构，但只给 token_digests，不回显 tokens 原文。

故障与边界：①账号为空、通道为空、通道含非字符串项、去重后超过 max_channels 抛 RECOVERY_INVALID，通道去重后按字典序保存，令牌按同一顺序发 tok-1、tok-2，记录与快照只留摘要；②hold_id 从 hold-1 递增，新单 state 为 pending，due_at 为申请时刻加 hold_seconds，confirmations 从 0 起；③同一账号已有 pending 请求时重复申请沿用原 hold_id、不重算 due_at、不并入新通道，merged 置真；④confirm_contact 只认本单通道，通道不在单上抛 RECOVERY_CHANNEL，令牌不符抛 RECOVERY_TOKEN，同一通道重复确认幂等、already 置真且不重复计数；⑤release 在 due_at 之前抛 RECOVERY_HOLD，确认数不足抛 RECOVERY_PENDING，非 pending 状态抛 RECOVERY_CLOSED；⑥release 在到期时刻含等于且确认数达标时放行，state 为 released，凭据形如 cred-N 只返回一次，releases 只计一次；⑦status 只读，remaining 为 due_at 减当前时刻且不小于 0，不改状态；⑧due_holds 只列 pending 且 due_at 已到的单，按 due_at 再按 hold_id 升序；⑨sweep 把到期且确认达标的单放行，返回 released 条数与 credentials 映射，到期的未达标单转 expired 并计数；⑩veto 需非空操作人与理由，撤销后 state 为 vetoed，重复撤销与撤销后放行都抛 RECOVERY_CLOSED；⑪另外三条必须处理：等待期内账号原持有人登录应视为自动否决、不能只发通知；多通道确认只到部分通道时不得提前放行、也不能无限延长等待期；交付后通道回执丢失只能重走整个等待期，不能重复展示同一凭据；⑫快照与恢复覆盖 holds、counters 与已用凭据计数，恢复后到期时间与确认进度不变、令牌摘要仍能校验，结构非法抛 RECOVERY_SNAPSHOT 且原状态不变。

硬约束：request、confirm_contact、veto、release 与快照全程持锁，同一请求被多路并发放行时只能成功一次、只能产出一份凭据，releases 计数不得错账；等待期按绝对到期时间持久化，重启后计时不重置；同一账号在途请求唯一，合并与放行互斥。stats 固定返回 requests、merged、confirmations、vetoes、releases、expired。

验收：`python3 -m pytest -q tests` 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发放行与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: recovery_hold_queue
- typeName: RecoveryHoldQueue
- file: recovery_hold_queue.py
