# batch50-py-game-a-10

## 题面

新副本的复活链路在上线首周被客服刷屏：同一具尸体被队友复活和原地复活同时结算，金币扣了两次、状态却只回到活人一次；还有玩家死亡前喊的队友复活，死后再点却判请求不存在；更有灵魂状态的角色离线一整晚，回来惩罚层数直接从三层变成零。范围是 gsb/batch50-py-game-a-10 的 resurrect_ledger.py，类 ResurrectLedger，负责死亡登记、三种复活方式的费用与冷却、灵魂惩罚叠加与衰减、队友复活请求的有效期；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：ResurrectLedger(*, penalty_window=60, max_stacks=5, costs=None, cooldowns=None)；register_character(character, *, gold=0, now=None)、state_of(character)、die(character, now=None)、resurrect(character, mode, now=None)、request_help(target, helper, now=None)、pending_request(target)、cancel_request(target)、penalty_of(character, now=None)、cooldown_of(character, mode, now=None)、expire_penalty(now=None)、mark_offline(character, now=None)、mark_online(character, now=None)、snapshot()、restore(state)、stats()。拒绝一律抛 ResurrectError(code, detail)。

故障与边界：①register_character 的 character 去空白后不得为空，重复登记报 RESURRECT_INVALID_REQUEST，初始状态固定为 character、state 为 alive、gold、stacks 为 0、deaths 为 0 五个字段，state_of 返回同一结构；②die 把活人置为 soul、deaths 加一、惩罚层数加一并截断在 max_stacks，惩罚窗口从本次死亡重新起算，返回 character、state、gold、stacks、deaths 五项，已死亡角色再死报 RESURRECT_ALREADY_DEAD；③resurrect 的 mode 只接受 in_place、town、teammate，默认费用 50、10、0，默认冷却 20、5、0 秒，costs 与 cooldowns 传入时覆盖默认值；④对活人复活报 RESURRECT_NOT_DEAD，模式不认识报 RESURRECT_INVALID_REQUEST，同角色同模式的剩余冷却大于 0 报 RESURRECT_COOLDOWN_ACTIVE，金币不足报 RESURRECT_INSUFFICIENT_FUNDS，失败时金币与状态都不得改动；⑤复活成功扣除费用、把 state 置回 alive、开启该模式冷却，返回 character、mode、state、gold、cost、stacks、deaths 七项，惩罚层数不会因为复活直接清零；⑥teammate 模式必须有 pending 的队友请求，否则报 RESURRECT_REQUEST_MISSING，成功后请求被消费；⑦request_help 的 target 与 helper 都必须是已登记角色且不能相同，相同报 RESURRECT_INVALID_REQUEST，未登记报 RESURRECT_UNKNOWN_CHARACTER，成功返回 target、helper、issued_at 三项，pending_request 返回同一结构；⑧角色死亡会清掉死亡前发出的复活请求，死亡后再发出的请求才有效，cancel_request 成功返回 True、无请求返回 False；⑨penalty_of 返回 stacks 与 remaining，remaining 是当前惩罚窗口的剩余秒数，cooldown_of 按 now 计算该模式剩余冷却，未到期时为正数；⑩expire_penalty 每个窗口只削一层惩罚并把窗口顺延，返回本次至少被削掉一层的角色数，同一时刻重复调用返回 0；⑪mark_offline 与 mark_online 维护离在线标记，灵魂状态下离线超过惩罚窗口后惩罚按剩余时间的一半衰减，而不是直接清零；⑫队友复活与原地复活同帧到达时只允许费用更低的一种生效，另一种自动取消。

硬约束：同一角色被两路复活并发命中时只能结算一次，金币只扣一次，stats.resurrected 与成功次数一致，另一次必须报 RESURRECT_NOT_DEAD，不能出现两个线程各自扣费；快照固定为 version、characters、stats 三个键，是深拷贝，restore 校验结构，缺键或类型不对报 RESURRECT_SNAPSHOT_INVALID 且原状态不被改动，恢复后灵魂状态、金币、惩罚层数与剩余时间、模式冷却、待处理请求都要继续可用，重启不能把死人直接复活。stats 至少含 registered、deaths、resurrected、requests、expired、cancelled 六项，其中 expired 累计惩罚削减次数。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: resurrect_ledger
- typeName: ResurrectLedger
