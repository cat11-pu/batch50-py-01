# batch50-py-game-a-03

## 题面

副本这周被玩家刷出两个漏洞：冰霜陷阱充能明明只剩一次，四个人同帧踩上去却扣了两次；同一个玩家在冷却里反复踩，机关的充能一直掉，最后整片机关提前失效；灭团重置之后，本来标了不可重置的符文机关也自己恢复满充能，进度直接白送，值班同学拿不到每一帧的结算顺序，只能靠录像回放推断。范围是 gsb/batch50-py-game-a-03 的 trap_trigger_orchestrator.py，类 TrapTriggerOrchestrator，维护副本内机关的布防状态、充能次数、触发半径、按玩家独立的冷却和实例级一次性标记。

公开接口：TrapTriggerOrchestrator(*, max_traps=16)；register_trap(trap_id, *, charges, radius, cooldown_frames=0, one_shot=False, reset_on_wipe=True)；register_player(player_id)；arm、disarm；trigger(trap_id, arrivals)；reset_instance()；charges_of、cooldown_of、rearmable、trap_state；snapshot、restore、stats。所有拒绝统一抛 TrapError(code, detail)。trap_state 返回 trap_id、charges、initial_charges、radius、cooldown_frames、one_shot、reset_on_wipe、armed 与 spent；reset_instance 返回 restored 与 left_alone 两个计数。

故障与边界：①register_trap 要求 charges、radius 为正整数、cooldown_frames 非负，重复登记报 TRAP_DUPLICATE_TRAP，参数非法报 TRAP_INVALID_REQUEST，登记数量超过实例上限报 TRAP_CAPACITY_EXCEEDED；②机关登记后默认未布防，未布防触发报 TRAP_NOT_ARMED，重复 arm 报 TRAP_ALREADY_ARMED，disarm 后已消耗的充能不回补；③trigger 的 arrivals 按到达顺序结算，每个成功触发的玩家消耗一点充能并记作 triggered，返回结果按到达顺序排列并带帧号，同一帧内同一玩家重复出现时按先后各判一次；④半径限制单帧最多结算的玩家数，超出的玩家返回 overflow 且不消耗充能，玩家名单与到达顺序都要保留；⑤充能在一帧内耗尽后，同帧后续玩家返回 depleted，机关自动转为未布防，下一帧触发按未布防拒绝；⑥one_shot 机关首次成功触发后永久失效，再 arm 报 TRAP_PERMANENTLY_SPENT，rearmable 为 False；⑦冷却期内的玩家再次触发只返回 cooldown 并累计拒绝计数，不消耗机关充能，同一玩家反复踩踏 charges_of 不得下降；⑧触发帧号自 1 递增，结算结果与统计按帧累加，重置实例不回退帧号；⑨灭团重置只恢复标为可重置的机关，重置后充能回到初始值、布防恢复、该机关的玩家冷却清零；⑩灭团重置不影响被标记为不可重置的机关及其已消耗充能；⑪未知机关或玩家报 TRAP_UNKNOWN_TRAP / TRAP_UNKNOWN_PLAYER，空 arrivals 报 TRAP_INVALID_REQUEST；⑫snapshot 要保留每个机关剩余充能、布防状态与每个玩家冷却剩余帧，restore 非法结构报 TRAP_SNAPSHOT_INVALID 且原状态不变。stats 至少含 traps、players、frames、triggered、cooldown_rejected、depleted、overflow、resets、arms、disarms。

硬约束：多线程同时触发同一机关时总消耗不得超过剩余充能，充能不得为负，帧号推进与结算必须在同一把锁内完成；快照恢复后帧号、充能与玩家冷却剩余要连续，不得与调用方共享可变结构；机关与玩家登记表受实例上限约束，长期副本不得因反复重置实例而无限增长，重置与触发竞争时也只能有一方生效。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: trap_trigger_orchestrator
- typeName: TrapTriggerOrchestrator
