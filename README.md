# batch50-py-game-a-04

## 题面

段位赛这周出了三类单子：玩家连胜两场点晋级没反应，再点一次提示还有系列赛进行中；有人在保护赛期间连败掉段，客服查了记录说保护次数根本没扣；系列赛超时之后胜场还挂在账上，玩家拿旧胜场反复找客服要补偿，后台又找不到一条完整的对局流水，运营想按段位与场次复算一遍，发现胜场、场次和系列赛状态三个口径互相对不上。范围是 gsb/batch50-py-game-a-04 的 rank_ladder_series.py，类 RankLadderSeries，管理玩家段位、晋级系列赛、保护赛与降级判定，赛季重置时清空进行中的系列赛但保留历史成绩。

公开接口：RankLadderSeries(*, ranks, wins_needed=2, losses_allowed=2, series_timeout=3600, protection_charges=1)；register_player(player_id, *, rank_index=0)；start_series(player_id, *, now=None)；report_match(player_id, *, match_id, result, now=None)；promote、demote；series_of、expire_series；standings、reset_season；snapshot、restore、stats。所有拒绝统一抛 RankError(code, detail)。start_series 返回系列赛记录，含 player_id、current_rank、target_rank、wins、losses、matches_left、status、started_at 与 expires_at；standings 返回段位、计数、系列赛状态与历史，历史条目按发生顺序追加，系列赛条目含 kind=series、result、wins、losses 与 rank，晋级与降级条目 kind 分别为 promoted 与 demoted。

故障与边界：①ranks 至少两段，wins_needed、losses_allowed 为正，rank_index 越界报 RANK_INVALID_REQUEST，配置非法报 RANK_INVALID_CONFIG，重复注册报 RANK_DUPLICATE_PLAYER；②同一玩家同时只能有一个进行中的系列赛，重复开赛报 RANK_SERIES_ACTIVE，最高段位不能开赛报 RANK_TOP_RANK，开赛后目标段位固定在下一段；③系列赛总场次为 wins_needed 加 losses_allowed，每场胜负都消耗一场，胜场先达标转 won、负场先达标转 lost，达标后剩余场次冻结；④同一 match_id 重复上报只算一次，第二次报 RANK_DUPLICATE_MATCH，并发上报同一场也只能计一分；⑤没有进行中系列赛时上报报 RANK_NO_SERIES，系列赛已结束再上报报 RANK_SERIES_CLOSED，result 非 win/loss 报 RANK_INVALID_REQUEST 且不消耗场次、不写历史；⑥promote 要求系列赛状态为 won，否则 RANK_NOT_ELIGIBLE，成功后段位加一、系列赛清空并记入历史，最高段位再晋级报 RANK_TOP_RANK；⑦保护赛生效期间连败到达降级线只扣保护次数，段位保持不变；⑧demote 在最低段位报 RANK_BOTTOM_RANK，段位与计数不变；⑨系列赛超时未打完按未完成处理，已攒胜场全部清空且不退还场次；⑩expire_series 未到超时时间时原样返回进行中的记录，不产生副作用；⑪reset_season 清空所有进行中的系列赛，返回清空数量，保留段位与历史成绩；⑫snapshot 深拷贝玩家、系列赛与计数，restore 非法结构报 RANK_SNAPSHOT_INVALID 且原状态不变。stats 至少含 players、series_started、matches_reported、wins、losses、duplicates、promotions、demotions、expired、season_resets、protection_used。

硬约束：同一玩家并发上报同一 match_id 只能计分一次，重复判定与计分必须在同一把锁内完成，场次与胜负计数不得出现负数；快照恢复后段位、系列赛胜负与剩余场次、保护次数、历史都要还原，且不得与调用方共享可变结构；每位玩家的对局去重集合与历史随赛季增长要有上限意识，赛季重置不得复制历史对象，计数与历史写入必须一起成功或一起不生效。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: rank_ladder_series
- typeName: RankLadderSeries
