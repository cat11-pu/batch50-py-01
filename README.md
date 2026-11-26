# batch50-py-game-a-04-p5

## 题面

赛季末结算这周被投诉了三次：一场对局里打野参团和输出都排第一，MVP 却给了对面刷了三十个人头的射手，玩家把战绩截图贴到论坛；另一场重开局的双方都被记了一胜一负，连胜加成还照发，队长说重开明明不算战绩；还有一场结算接口超时重试，同一次上报进来两遍，连胜加成发了两份，第二天榜单上多出一截分数；挂机玩家在泉水里站了整场，结算照样进 MVP 评选，队友要求回滚。问题集中在 MOBA 对局结算，改动范围是 gsb/batch50-py-game-a-04-p5 的 moba_match_settlement.py，类名 MobaMatchSettlement，按上报的双方参战数据计算表现分、评出 MVP、累加连胜加成并维护玩家段位记录。所有时刻由调用方以毫秒整数传入。

公开接口：MobaMatchSettlement(*, win_points=20, loss_points=12, mvp_bonus=30, streak_step=5, streak_cap=5, afk_ratio=0.3, max_players=10)；mvp_score(line)；report_match(match_id, *, duration, players, winner, mode="normal", now=0)；settlement(match_id)；player_summary(player_id)；leaderboard(*, limit=None)；afk_players(match_id)、mvp_of(match_id)、streak_bonus(player_id)；snapshot()、restore(state)、stats()。players 是 PlayerLine 序列，字段为 player_id、team、kills、deaths、assists、damage_dealt、damage_taken、vision_score、active_ratio。拒绝统一抛 MobaError(code, detail)。

故障与边界：①match_id 为空、duration 非正、players 少于两人或超过 max_players 或不是 PlayerLine、队伍不在 blue 与 red 内、玩家 id 重复、击杀死亡助攻承伤视野为负、active_ratio 越界、mode 非法、正常局 winner 缺失，一律 MATCH_INVALID_REQUEST 且不登记任何玩家；②双方必须都有参战玩家，缺一边整场拒绝；③表现分为 kills*3 + assists*2 - deaths*2 + damage_dealt//1000 + damage_taken//1500 + vision_score//10，全部整数运算，允许为负；④MVP 只从获胜方选，按表现分降序，平分先比死亡数少者，再比玩家 id 字典序，获选者额外加 mvp_bonus 并累加 mvp_count；⑤active_ratio 低于 afk_ratio 判为挂机，挂机玩家记入 afk 列表，不参加 MVP 评选，不发任何段位分，不记胜败场次与连胜；⑥正常局胜方每人加 win_points，败方每人扣 loss_points，败方连胜清零，best_streak 只增不减；⑦连胜加成按 1 起的连胜数乘 streak_step，并在 streak_cap 处封顶，只发给非挂机的胜方玩家，streak_bonus 查询返回该玩家最近一场实际获得的加成；⑧rating_delta 与 streak_bonus 覆盖本场全部玩家，挂机与败方没有加成时记 0，scores 也覆盖全部玩家；⑨settlement、mvp_of、afk_players、player_summary、streak_bonus 查询未知 id 一律 MATCH_UNKNOWN；⑩leaderboard 按段位降序、玩家 id 升序返回，limit 必须是正整数或 None；⑪快照包含 version、players、matches、counters、stats，players 与 matches 以玩家或对局 id 为键，深拷贝不与内部共享，恢复时版本、结构或类型不符抛 MATCH_SNAPSHOT_INVALID 且原状态不变；⑫stats 固定返回 matches、players、mvps、afk_flags、top_streak、rating_awards、streak_awards、refused_reports 八项。

策划侧另外点名三条：重开局不计连胜也不计败场，双方都不掉分；挂机判定后该玩家不参与 MVP 评选，但队伍胜负与其余人的加分不变；同一 match_id 重复上报必须幂等，返回同一份结算结果，不能二次发放连胜加成。

硬约束：上报与快照共用一把锁，并发上报不同对局时玩家段位、连胜与统计必须一致，同一玩家不会因为交错写入丢掉胜场；快照恢复后段位、连胜、best_streak、MVP 次数、对局记录与统计必须原样续上，恢复后再报一场的结果要与未中断时逐字段相同；单场参战人数受 max_players 硬顶，连胜加成受 streak_cap 硬顶。验收运行 `python3 -m pytest -q tests`，15 条全部通过；不得修改测试、跳过用例或按固定输入写死；并发与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: moba_match_settlement
- typeName: MobaMatchSettlement
