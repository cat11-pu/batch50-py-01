# batch50-py-game-a-07

## 题面

周五的联赛服在占点图上连出三件怪事：同一据点红蓝两侧的进度条同时显示过半，比分却纹丝不动；一支队伍已经领先两百多分，比赛还硬拖到加时才结束；还有一场双方在加时把六个据点全占满，结算直接判了平局。范围是 gsb/batch50-py-game-a-07 的 domination_scoreboard.py，类 DominationScoreboard，负责一局占点模式的据点争夺、按时结算、加时推进与提前结束判定；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：DominationScoreboard(*, teams=("red", "blue"), mercy_gap=200, tick_points=10, round_seconds=120, overtime_seconds=30, lock_ticks=3)；register_point(point_id)、point_state(point_id)、capture_tick(point_id, team, amount)、settle(seconds=1)、score_of(team)、points_held(team)、overtime()、mercy_check()、finalize()、snapshot()、restore(state)、stats()。拒绝一律抛 DominationError(code, detail)。

故障与边界：①register_point 的 point_id 去空白后不得为空，重复登记报 DOMINATION_INVALID_REQUEST，初始记录固定为 point_id、controller 为空、progress 为 0、locked 为 0 四个字段；②争夺进度只保留一个带符号整数 progress，取值 -100 到 100，正值偏向 teams[0]、负值偏向 teams[1]，任何时刻不可能两侧同时为正；③capture_tick 的 team 必须是登记队伍之一，amount 必须为正整数，违反报 DOMINATION_INVALID_REQUEST，据点未登记报 DOMINATION_UNKNOWN_POINT；④进度朝该队伍方向累加并截断在 ±100，达到满值时控制权交给该队伍、progress 归零、locked 置为 lock_ticks 并计入一次易主，超出部分不顺延，capture_tick 与 point_state 返回同一结构的据点记录；⑤锁定期间任何推进都被忽略、不报错，只增加 stats.ignored，锁定计数由 settle 递减；⑥已经控制据点的队伍继续推进，满值只把进度清零，不产生易主也不重新锁定；⑦settle 每个结算刻按各自控制据点数乘 tick_points 涨分，返回 ticks、awarded、clock、overtime 四项，awarded 是这段时间内按队伍累计的分数，未进入加时时 overtime 为 active 假、remaining 0、trailing 空，同时递减回合时钟与锁定计数；⑧回合时钟归零时若比分不等则进入加时，落后方为追赶方，剩余时间取 overtime_seconds；⑨加时期间只有追赶方在该结算刻之前占过点，剩余时间才减一，领先方占点不推进加时时钟；⑩加时剩余时间归零即结束，finalize 按比分判胜负并给出 overtime；⑪分差达到 mercy_gap 时提前结束，mercy_check 返回 triggered、gap、leader，finalize 给出 mercy；⑫finalize 只能在提前结束或时间走完后调用，返回 winner、scores、reason 三项，否则报 DOMINATION_ROUND_ACTIVE，stats.finalized 按调用次数累计。

硬约束：同一据点被多路 capture_tick 并发推进时 progress 必须始终落在 ±100 内，控制权至多一次易主，stats.captures 与成功推进次数一致，不能出现两侧同时为正或负数进度挂在错误队伍名下；快照固定为 version、points、scores、clock、overtime、mercy、stats 七个键，是深拷贝，restore 校验结构，缺键或类型不对报 DOMINATION_SNAPSHOT_INVALID 且原状态不被改动，恢复后时钟、锁定、加时剩余与比分都要继续可用，重启不能把已占据点清成中立。分差提前结束只在整点结算时检查，据点易主当帧不触发；加时阶段双方同时占满全部据点时，按最后一次易主方判定胜负。stats 至少含 points、captures、flips、ignored、ticks、mercies、finalized 七项。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: domination_scoreboard
- typeName: DominationScoreboard
