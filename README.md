# batch50-py-game-a-09

## 题面

三线合服后的第一个世界首领周，伤害榜和血条对不上：三条分线各自都显示打掉了三成血，首领面板却只掉了不到两成；第二只首领被击杀后，迟到的分线补交伤害又把击杀者改成了别人；还有一次两条分线合并后，同一批伤害被重复计入，补偿发了两遍。范围是 gsb/batch50-py-game-a-09 的 shard_boss_ledger.py，类 ShardBossLedger，负责把多条分线的伤害片段汇总成一份首领账本、按序号去重、推进阶段并在血量归零时冻结结算；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：ShardBossLedger(*, max_hp=100000, phase2_at=0.5)；register_shard(shard_id)、shard_report(shard_id)、apply_damage(shard_id, segment_seq, damage, *, actor=None)、freeze(reason="manual")、merge_shards(source, target)、boss_state()、frozen_shards()、snapshot()、restore(state)、stats()。拒绝一律抛 ShardError(code, detail)。

故障与边界：①register_shard 的 shard_id 去空白后不得为空，重复登记报 SHARD_INVALID_REQUEST，初始报告固定为 shard_id、segments、damage、max_seq 四个字段且都从 0 起；②片段序号在单条分线内唯一，不同分线各自从 1 编号，同一分线重复提交同一序号报 SHARD_DUPLICATE_SEGMENT 且血量不再变化；③segment_seq 必须为正整数、damage 必须为正整数，违反报 SHARD_INVALID_REQUEST，分线未登记报 SHARD_UNKNOWN_SHARD，apply_damage 返回 shard_id、segment_seq、accepted、damage、hp、phase、status 七项；④片段允许迟到与乱序，序号不必连续，max_seq 取该分线见过的最大序号，segments 与 damage 按实际接受的片段累计；⑤总血量按接受片段的伤害递减并截断在 0，超出部分计入 stats.overkill，血量大于 max_hp 与 phase2_at 的乘积时阶段为 phase-1，血量降到该阈值及以下且仍大于 0 时为 phase-2；⑥血量归零时立即冻结全部分线并进入 settlement 阶段，击杀者取把血量打到 0 的那条片段的 actor，stats.freezes 只计一次；⑦freeze 可在任意时刻手动调用，把 status 与 phase 都置为 settlement 且不产生击杀者，返回 status、phase、frozen_shards 三项，重复冻结幂等且不重复计数；⑧冻结后 frozen_shards 返回全部分线编号并按字典序升序，不区分是否提交过伤害；⑨merge_shards 把来源分线的片段并入目标分线，保留目标已有记录、删除来源分线，返回 source、target、moved、skipped 四项，总血量与总伤害不得因为合并而变化；⑩合并时同一序号只保留一份，重复的计入 skipped；来源或目标未登记报 SHARD_UNKNOWN_SHARD，来源与目标相同报 SHARD_INVALID_REQUEST，已冻结账本报 SHARD_BOSS_FROZEN；⑪boss_state 固定返回 hp、max_hp、phase、status、killer、segments、damage 七个字段，status 只有 active 与 settlement 两种；⑫冻结后到达的伤害片段计入伤害统计但不改变击杀归属与阶段，分线合并按片段序号去重，不按各分线自报的累计伤害值去重。

硬约束：多条分线并发提交同一序号时只能有一条被接受，其余必须报 SHARD_DUPLICATE_SEGMENT，stats.segments 与 accepted 次数一致，血量不得出现负数，也不能在血量归零后再触发一次冻结；快照固定为 version、boss、shards、frozen、stats 五个键，是深拷贝，restore 校验结构，缺键或类型不对报 SHARD_SNAPSHOT_INVALID 且原状态不被改动，恢复后血量、阶段、各分线已接受序号与冻结状态都要继续可用，重启不能把已冻结的首领放回 active。stats 至少含 registered、segments、duplicates、damage、overkill、freezes、merged 七项。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: shard_boss_ledger
- typeName: ShardBossLedger
