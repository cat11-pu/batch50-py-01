# batch50-py-game-a-05-p5

## 题面

竞速服幽灵回放和排行榜被打回：有人两次提交同一圈，榜上两条；抄近道一圈照样进前十；幽灵回放跑到一半就断，时长比圈速短；重启后跑圈消失。范围是 gsb/batch50-py-game-a-05-p5 的 time_trial_ghost_ledger.py，类 TimeTrialLedger，记录检查点顺序与分段、校验捷径与逆行、保存最佳圈采样并压缩。

公开接口：start_run(player, track_id)、checkpoint(index, at_ms)、finish_run(at_ms) 返回 LapRecord、validate、submit、ghost_samples、leaderboard、snapshot、restore、stats，拒绝抛 TrialError(code, detail)。

故障与边界：①单实例只许一个跑圈进行中，重复开跑 TRIAL_RUN_ACTIVE，无跑圈 checkpoint 报 TRIAL_NO_ACTIVE_RUN；②检查点序号须为 [0, count) 内整数，否则 TRIAL_INVALID_REQUEST；③跳号判捷径 TRIAL_SHORTCUT、整圈作废，finish 报 TRIAL_RUN_INVALID；④重复通过只认第一次，不刷新分段、不补缺失点；⑤逆行后再正向过，整圈作废；⑥分段为累计差，掩码按位记录；⑦finish 要求掩码齐全，否则 TRIAL_INCOMPLETE 且跑圈可续；⑧提交掩码须与赛道匹配，否则 TRIAL_MASK_MISMATCH，同玩家同赛道留更快合法一圈；⑨幽灵采样从 0 起，压缩回放时长须等于圈速、末点保留；⑩并发提交同玩家只留最快；快照恢复后跑圈、掩码、最佳成绩都在、不共享结构，restore 非法报 TRIAL_SNAPSHOT_INVALID。

硬约束：checkpoint、finish、submit 同锁串行，同玩家并发提交只留最快且合法的一圈；快照恢复后进行中进度、采样、最佳成绩都在且不共享结构。stats 含 runs_started、laps_finished、submitted、rejected、invalidated。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、写死；并发自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: time_trial_ghost_ledger
- typeName: TimeTrialLedger
