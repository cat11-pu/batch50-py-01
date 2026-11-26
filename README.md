# batch50-py-safety-c-12

## 题面

安全运营中心上季度把六条分散告警拼成一条攻击链时出了岔子：边界设备先报侦察扫描，随后主机侧报可疑执行，两条记录的时间戳相差四十秒、到达顺序颠倒，平台把它们拆成两条孤立链，值班同学按单点告警分别关闭；另一条已经判定结束的链在两天后又被一条迟到的横向移动事件改了阶段，复盘时没人说得清当时的处置依据。还有一次水位线被回拨，重复告警瞬间翻了三倍。范围是 gsb/batch50-py-safety-c-12 下的 attack_chain_correlator.py，类名 AttackChainCorrelator：按来源与目标组合关联事件、维护乱序窗口与水位线、在静默超时后关闭链并固化阶段序列。

公开接口：AttackChainCorrelator(*, reorder_window=120, silence_timeout=600)；ingest(event_id, *, src, dst, stage, ts)；advance_watermark(*, ts)；watermark()；close_stale(*, now)；close_chain(chain_id, *, reason, now)；chain_of(chain_id)；chains(*, state=None)；chain_for_event(event_id)；stages()；snapshot()；restore(state)；stats()。拒绝时抛 ChainError(code, detail)，链用只读对象 Chain 返回（含 chain_id、src、dst、stage、stages、events、state、isolated、opened_at、last_event_at、closed_at、close_reason），ingest 返回 event_id、chain_id、stage、attached、isolated，时间统一为带 +00:00 偏移的 ISO 8601 字符串。

故障与边界：①阶段只能取 reconnaissance、initial_access、execution、persistence、exfiltration、impact 六个之一，非法阶段抛 CHAIN_BAD_STAGE；event_id、src、dst 必须为非空字符串，否则 CHAIN_BAD_REQUEST；重复 event_id 抛 CHAIN_DUPLICATE_EVENT。②关联键是 src 与 dst 的组合，首次事件开一条 open 链，attached 与 isolated 均为假，stages 只含首阶段、events 为 1、opened_at 与 last_event_at 都是事件时间。③同一链后续事件阶段只进不退：只有阶段序号更大才推进 stage 并追加到 stages 序列；同一阶段重复上报不得推进阶段，但 events 计数照常累加。④晚于水位线之前但在 reorder_window 之内的事件要补挂到该键当前 open 链，attached 为真，阶段仍按只进不退处理，last_event_at 取已见事件的最大时间。⑤早于水位线减 reorder_window 的事件一律落成孤立链：isolated 与 attached 分别为真和假，单独 chain_id，不得改写该键原有链的阶段与计数。⑥乱序窗口之外的迟到事件不得改写已经关闭的链，也不得让关闭链回到 open；关闭链的阶段序列以关闭时固化的为准。⑦advance_watermark 只允许单调前进，回退抛 CHAIN_WATERMARK_REGRESSION，相同时间幂等；尚未推进时 watermark 返回 None。⑧close_stale 按 last_event_at 加 silence_timeout 判断，不晚于 now 的链关闭并返回本次关闭的 chain_id 元组（按标识升序），closed_at 记录关闭时间，关闭后不得再追加阶段。⑨close_chain 手动关闭未知链抛 CHAIN_UNKNOWN_CHAIN，重复关闭抛 CHAIN_ALREADY_CLOSED，关闭原因写入 close_reason。⑩chain_for_event 对每个已接收事件（含孤立链事件）返回所属 chain_id，未知事件抛 CHAIN_UNKNOWN_EVENT；chains 可按 state 过滤并按 chain_id 升序。⑪快照包含版本、链、事件索引、水位线与计数，恢复非法结构抛 CHAIN_SNAPSHOT_INVALID 且不改动现有数据。⑫重启后水位线、关闭状态与固化阶段序列原样恢复，不能把已关闭链恢复成 open；stats 返回 ingested、opened、isolated、closed 四项。

硬约束：同一时间窗内并发 ingest 必须串行，同一关联键只能开出一条 open 链，事件不得丢失且每个事件都能通过 chain_for_event 查到；水位线推进、链关闭与快照恢复不得交错，关闭链的阶段序列一经固化，任何恢复或迟到事件都不能改写。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: attack_chain_correlator
- typeName: AttackChainCorrelator
