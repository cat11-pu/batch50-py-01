# batch50-py-safety-c-18

## 题面

复测批次这个季度被审计问了三次。第一次是批次还没测完就被节点负责人点了关闭，报告里半数发现没有结论，客户拿着报告来问到到底修没修；第二次是一个已经确认修复的发现，客户在下一个版本又复现了，我们只能另开一个新批次重新登记，回归次数统计不到，季度指标失真；第三次是同一份发现前后登记了两条不同结论，报告里取的是先填的那条，整改说明和实际状态对不上。范围是 gsb/batch50-py-safety-c-18 的 retest_cycle_ledger.py，类名 RetestCycleLedger，负责批次开启、逐项结论登记、关闭门槛与关闭后的回归重开。

公开接口：RetestCycleLedger(*, max_rounds=5)；open_batch(batch_id, *, findings, now, owner="") -> dict；add_findings(batch_id, findings, *, now) -> dict；record_result(batch_id, finding_id, *, conclusion, evidence="", note="", now) -> dict；reopen(batch_id, finding_id, *, reason, now) -> dict；close_batch(batch_id, *, actor, now) -> dict；pending(batch_id)；summary(batch_id)；history(batch_id)；batches()；stats()；snapshot()；restore(state)。拒绝时抛 LedgerError(code, detail)。

故障与边界：①批次编号不能为空且不可重复，分别抛 LEDGER_BAD_BATCH 与 LEDGER_DUPLICATE_BATCH。②发现编号不能为空，同一次登记里不能重复出现，否则抛 LEDGER_BAD_FINDING；批次里已有的编号再次登记只忽略，不重复记录。③结论只认 fixed、still_present、not_reproducible 三个字面值，大小写与前后空格都不放宽，否则抛 LEDGER_BAD_CONCLUSION。④still_present 必须附非空证据，否则抛 LEDGER_EVIDENCE_REQUIRED，该项仍算未结论。⑤未登记的批次与未登记的发现分别抛 LEDGER_UNKNOWN_BATCH、LEDGER_UNKNOWN_FINDING。⑥批次关闭要求所有发现都有结论，缺哪几条要在错误详情里按编号升序列出，抛 LEDGER_INCOMPLETE。⑦关闭回执给出关闭人、关闭时刻、轮次、回归次数与三项结论计数。⑧重复关闭抛 LEDGER_ALREADY_CLOSED，关闭之后再登记结论同样拒绝。⑨只有结论为 fixed 或 not_reproducible 的项可以重开，still_present 的项重开抛 LEDGER_BAD_REOPEN；批次还开着时重开抛 LEDGER_BATCH_OPEN；理由为空也抛 LEDGER_BAD_REOPEN。⑩重开把批次拉回 open、轮次加一、回归次数加一，被重开的项回到待结论，其余项的结论保留。⑪同一发现重复登记结论以最后一次为准，但前次结论必须完整留在历史里，history 按登记先后返回。⑫批次关闭后不允许追加新发现，只能另开一个新批次。

历史条目给出发现编号、结论、轮次、登记时刻、证据与备注；统计给出 batches、open、closed、records、reopens、regressions、findings 七项。

硬约束：同一批次的登记、重开与关闭必须串行，关闭判定与状态落定之间不得插入其它变更，重开要么整批回到 open 要么一点都不改；快照与活动状态完全脱钩，恢复后轮次、回归次数、历史与待结论项原样回来，非法快照抛 LEDGER_SNAPSHOT_INVALID 且不改动现有数据，重启后不得把已关闭批次借快照退回更早的轮次。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: retest_cycle_ledger
- typeName: RetestCycleLedger
