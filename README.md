# batch50-py-game-a-11

## 题面

周三凌晨例行维护后，三支固定队的副本钥匙集中报障：同一队伍同一周重开同一层，每把钥匙上滚出来的词缀都不一样，队员没法提前配装，治疗还带着上上周的抗性进本；周二按时打完的钥匙时长没有累加，周四再进直接被判超时，队长坚称系统吞掉了奖励时间；灭团两次后钥匙凭空消失，队伍查不到剩余次数，客服只能手工补发；维护后没用掉的低层钥匙既没降级也没换词缀，同一把钥匙在队长和队员界面上显示的等级还对不上，客服连一条可核对的记录都拿不出来。问题集中在本周新上的钥匙模块，改动范围是 gsb/batch50-py-game-a-11 的 dungeon_key_affixer.py，类名 DungeonKeyAffixer，钥匙的生成、进本、结算、失败和每周重置都由它负责，本周已按 P2 处理。目前台账只保留最近一次结算结果，重启之后连当周的词缀都复现不出来，运营要求这次把跨周与重启恢复一并补齐。

公开接口：DungeonKeyAffixer(*, affix_pool, affixes_per_key=3, min_level=1, max_level=15, base_time=600, bonus_time=90, attempts=5, weekly_floor=1, start_week=1)；roll_key(key_id, party, level, *, week)、enter(key_id)、complete(key_id, *, elapsed)、fail(key_id)、affixes_for(party, level, *, week)、level_of(key_id)、key_of(key_id)、weekly_reset(*, week)、snapshot()、restore(state)、stats()。所有拒绝统一抛 DungeonKeyError(code, detail)。

返回值约定：钥匙视图包含 key_id、party、level、week、affixes、time_limit、time_spent、attempts_left、completions、status；结算结果包含 within_limit、bonus_granted、downgraded、level、completions。

故障与边界：①等级必须落在 min_level 到 max_level 之间，越界或非整数抛 KEY_LEVEL_OUT_OF_RANGE；②词缀由周次、队伍、等级共同决定，取 affixes_per_key 个互不相同的词缀并按字典序排列，跨实例、跨调用结果一致，词缀池不足以取满时直接拒绝生成，同一 key_id 反复读取必须返回同一份记录；③key_id 与队伍名不能为空，key_id 重复登记抛 KEY_DUPLICATE；④只有 fresh 状态的钥匙能进本，重复进本抛 KEY_STATE_CONFLICT，已耗尽的钥匙进本抛 KEY_ATTEMPTS_EXHAUSTED；⑤按时通关（elapsed 不超过剩余时长）给该钥匙累加 bonus_time，通关次数加一、计时清零、钥匙回到可用状态；⑥超时通关只降一级，词缀组合原样保留，也不发放加时奖励；⑦失败保留钥匙但扣一次尝试，扣到零置为 depleted，钥匙仍留在台账里可查；⑧周重置只处理未进本的钥匙，正在战斗中的钥匙顺延到下一次，被顺延的钥匙在下一轮重置时仍按未使用处理，返回 downgraded、deferred、week 三个计数；⑨跨周降级后的等级不得低于 weekly_floor，触底后保持不变；⑩未知 key_id 的查询、进本与结算统一抛 KEY_NOT_FOUND；⑪stats 固定返回 keys、fresh、active、depleted、entered、clears、failures、resets、week 九项；⑫快照必须与实时状态完全隔离，结构缺项或类型不对抛 KEY_SNAPSHOT_INVALID，且不得破坏已有数据。

硬约束：同一把钥匙的并发进本只能有一个成功，其余必须拿到 KEY_STATE_CONFLICT，entered 计数不得多算，同一队伍并发登记不同钥匙时词缀不得串号，每次进本与结算都要在锁内一次完成，不得出现半更新状态；快照恢复后等级、词缀、剩余时长、尝试次数、通关次数与全部统计必须和恢复前一致，且不与快照共享任何可变结构。

验收：`python3 -m pytest -q tests` 15 条全过；不得修改测试、跳过用例或针对固定输入写死；并发、重启与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: dungeon_key_affixer
- typeName: DungeonKeyAffixer
