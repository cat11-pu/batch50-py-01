# batch50-py-game-a-13

## 题面

周末首杀团连着报了三类事故：灭团后首领血量没有回到检查点，阶段还停在灭团前那一档，复活起来直接被打穿；同一次灭团被插件和日志各上报一遍，灭团次数翻倍，三次机会一晚上就耗光；打到第四次时队伍既没被退回副本入口，也没有任何提示，全员只能下线重开；还有一次通关后重新进本，首领又生成了一份满血检查点，累计灭团次数被清零，客服对不上账；恢复过程中插件还在继续上报伤害，仇恨表被写进一堆无效记录。改动落在 gsb/batch50-py-game-a-13 的 wipe_recovery_ledger.py，类名 WipeRecoveryLedger，负责进战、检查点推进、灭团恢复、通关与副本重置。值班 GM 现在只能靠录屏逐帧核对，运营要求把检查点、灭团账目与恢复窗口一次性写清楚。

公开接口：WipeRecoveryLedger(*, attempts_per_lockout=3)；enter_combat(boss_id, *, hp_max=1000, phase=1)、advance_phase(boss_id, *, phase, hp)、add_effect(boss_id, kind, name)、damage(boss_id, amount, source)、wipe(boss_id)、recover(boss_id)、mark_clear(boss_id)、progress_of(boss_id)、attempts_left(boss_id)、threat_of(boss_id)、reset_instance()、snapshot()、restore(state)、stats()。所有拒绝统一抛 RecoveryError(code, detail)。

返回值约定：战斗进度包含 hp、hp_max、phase、status、consecutive_wipes、total_wipes、attempts_left、checkpoint_hp、checkpoint_phase、buffs、summons；恢复结果包含 restored_hp、restored_phase、cleared_buffs、cleared_summons、attempts_left、ejected。

故障与边界：①进本时建立检查点并重置尝试次数，进本后状态为 engaged，同一场战斗重复进本抛 RECOVERY_ALREADY_ENGAGED；②阶段只能严格前进，检查点同步跟到最新的阶段与血量，阶段回退或持平抛 RECOVERY_PHASE_REGRESSION；③灭团把状态切到 recovering，连续灭团与累计灭团各加一、尝试减一，同一场战斗重复上报只计一次，不重复扣次数，上报的来源和时间戳不影响计数；④恢复按检查点回血回阶段，清空战斗增益与召唤物，add_effect 的 kind 只接受 buff 与 summon，其他取值抛 RECOVERY_INVALID_EFFECT；⑤不在 recovering 状态调用恢复抛 RECOVERY_NOT_RECOVERING，恢复必须一次完成，不能只回血不回阶段；⑥尝试扣到零直接置为 ejected，此时恢复抛 RECOVERY_EJECTED，再次进本同样抛 RECOVERY_EJECTED，ejected 状态下所有战斗操作都被拒绝，必须走 reset_instance 才能重开，reset_instance 返回 bosses 与 wipes_cleared 两个计数；⑦通关把状态置为 cleared、尝试归零，累计通关加一；⑧恢复窗口内到达的伤害请求必须被拒绝，且不得计入仇恨表；⑨已通关的首领在副本重置前不再生成检查点，重复进入也不重置灭团计数；⑩未知首领的查询与操作统一抛 RECOVERY_BOSS_UNKNOWN；⑪stats 固定返回 bosses、engaged、recovering、cleared、ejected、wipes、recovers、clears、resets 九项；⑫快照必须深拷贝，非法结构抛 RECOVERY_SNAPSHOT_INVALID 且原状态保持不变。

硬约束：同一场战斗的并发灭团上报只能计一次，连续灭团、累计灭团与剩余尝试不得多扣，恢复与通关的并发调用不得互相覆盖，状态迁移必须一步到位；快照恢复后检查点阶段与血量、累计灭团次数、尝试余额、增益与召唤物清空状态必须与恢复前一致，且不与快照共享可变结构。

验收：`python3 -m pytest -q tests` 15 条全过；不得修改测试、跳过用例或针对固定输入写死；并发、重启与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: wipe_recovery_ledger
- typeName: WipeRecoveryLedger
