# batch50-py-game-a-06

## 题面

新赛季上线后，死灵法师的召唤流出了两拨互相矛盾的工单：一拨说骷髅刷到第四只时最早那只凭空消失，另一拨说团灭重进副本后场上还挂着上一局的召唤物，而召唤冷却已经转好。范围是 gsb/batch50-py-game-a-06 的 summon_lifecycle.py，类 SummonLifecycle，负责战斗内召唤物的登记、剩余时间推进、所有者变更与离线回收；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：SummonLifecycle(*, per_owner_cap=3, offline_grace=30, default_ttl=60, default_cooldown=10, cooldowns=None)；summon(owner, kind, *, ttl=None, inherit=1.0, now=None)、dismiss(owner, summon_id)、tick(seconds)、transfer_owner(summon_id, new_owner, now=None)、list_of(owner)、remaining_of(summon_id)、cooldown_of(owner, kind)、owner_offline(owner, now=None)、owner_online(owner, now=None)、reap_owner(owner, now=None)、snapshot()、restore(state)、stats()。拒绝一律抛 SummonError(code, detail)。

故障与边界：①summon 的 owner、kind 去空白后不得为空，ttl 必须为正整数，inherit 必须落在 (0, 1] 内，ttl 省略取 default_ttl，违反任一项报 SUMMON_INVALID_REQUEST；②召唤物编号从 s0001 起按全局召唤序号递增，记录含 summon_id、seq、owner、kind、remaining、inherit、created_at 七项，seq 也用于同剩余时间时的淘汰排序；③同一所有者的同一 kind 有独立冷却，冷却未转好再召唤报 SUMMON_COOLDOWN_ACTIVE，不同 kind 互不影响，tick 同时推进剩余时间与冷却；④每个所有者的在场召唤物不得超过 per_owner_cap，超限时淘汰剩余时间最少的那一只并计入 stats.evicted，新召唤物照常入场；⑤dismiss 只接受所有者本人，成功返回 True，编号不存在报 SUMMON_UNKNOWN_SUMMON，所有者不匹配报 SUMMON_OWNER_MISMATCH；⑥tick 只接受正整数秒，返回本次消散的编号列表并按序号升序，剩余时间递减到 0 即消散并计入 stats.expired；⑦transfer_owner 保留原剩余时间与 seq，只改归属，转入方已达上限时先淘汰转入方剩余时间最少的一只，编号不存在报 SUMMON_UNKNOWN_SUMMON，转入方为空报 SUMMON_INVALID_REQUEST；⑧list_of 只返回该所有者当前在场的召唤物并按 seq 升序，不掺入已消散或已转出的记录；⑨owner_offline 记录首次离线时刻并返回 owner、offline_at 两项，重复调用不覆盖原时刻，owner_online 清除离线标记；⑩reap_owner 只在离线时长达到 offline_grace 后清空该所有者的全部召唤物并返回数量，未达宽限期返回 0 且一只都不动，从未离线的重复回收同样返回 0；⑪所有者离线超过宽限期后召唤物消散但不返还冷却，召唤次数照常计入；⑫上限淘汰在剩余时间相同时按召唤序号升序移除，不按字典序。

硬约束：同一所有者被多路并发召唤时不能超出上限，也不能丢掉任何一次成功登记的编号，seq 不得重复，stats.summoned 与成功次数一致，淘汰只发生在拿到同一把锁的临界区里；快照固定为 version、seq、summons、owners、cooldowns、stats 六个键，是深拷贝，restore 校验结构，缺键或类型不对报 SUMMON_SNAPSHOT_INVALID 且原状态不被改动，恢复后剩余时间、冷却与淘汰次序都要继续可用，重启不能把在场召唤物清空。时间统一用 ISO8601 UTC 字符串，now 省略时取当前 UTC，离线时长按解析后的时刻比较。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: summon_lifecycle
- typeName: SummonLifecycle
