# batch50-py-safety-c-20

## 题面

上个月的算力分配被安全委员会点了两次名。第一次是新接进来的两个目标，第一轮就被压到最低配额，跑了半天没覆盖几个分支，负责人说这是明摆着的饥饿；第二次是总预算临时砍掉三成，结果几个重点目标被直接清零，而产出一直为零的老目标反而还占着原来的份额，等于把预算喂给了不出货的机器。还有一次更诡异，同样的目标列表和同样的产出记录，两台机器算出来的分配结果不一样，复盘时对不上账。范围是 gsb/batch50-py-safety-c-20 的 fuzz_budget_allocator.py，类名 FuzzBudgetAllocator，负责目标登记、逐轮预算分配、产出反馈、衰减与观察态。

公开接口：FuzzBudgetAllocator(*, floor_quota=64, yield_threshold=1)；register(target, *, weight=1.0, note="") -> dict；allocate(total_budget) -> dict[str, int]；report_yield(target, *, new_coverage=0, crashes=0) -> dict；rebalance(*, total_budget) -> dict[str, int]；consume(target, units) -> int；usage()；targets()；states()；round_no()；stats()；snapshot()；restore(state)。拒绝时抛 AllocError(code, detail)。

故障与边界：①目标名不能为空且不可重名，分别抛 ALLOC_BAD_TARGET 与 ALLOC_DUPLICATE_TARGET；权重取 0 到 100 的开区间，越界抛 ALLOC_BAD_WEIGHT。②round_no 从零起，每次 allocate 推进一轮；总预算必须是正整数，零、负数、字符串与浮点都拒，抛 ALLOC_BAD_BUDGET；一个目标都没登记时抛 ALLOC_NO_TARGETS。③产出分等于新覆盖数乘三加崩溃数乘五，两个入参必须是非负整数，否则抛 ALLOC_BAD_YIELD，未登记目标抛 ALLOC_UNKNOWN_TARGET。④每轮先给每个目标保底 floor_quota，余额按有效权重用整数最大余数法分摊，余数相同时按目标名升序各补一个单位，结果按目标名升序返回且总和必须等于总预算。⑤有效权重等于注册权重乘以产出系数再乘衰减系数，产出系数随累计产出单调不减，衰减系数在上轮有产出时为 1，连续零产出时每轮减半且不低于八分之一。⑥连续零产出达到三轮的目标进入 observing 观察态，观察态不是停投，分配仍不得低于保底。⑦新注册的目标首轮要给探索配额，不能因为还没有历史产出就被压到保底以下。⑧总预算不足以覆盖全部保底时按有效权重等比缩放，但保底额度优先满足。⑨rebalance 只算下一轮的投影，不改轮次、不改衰减与已用量，紧接着调 allocate 必须得到同一份结果。⑩consume 从已分配额度里扣减，超额抛 ALLOC_BUDGET_EXHAUSTED 且不动已用量，单位非正抛 ALLOC_BAD_UNITS。⑪usage 给出轮次与已分配、已消耗、剩余三张表；统计给出 rounds、targets、observing、yield_reports、allocated_total、consumed_total 六项。⑫相同的目标、相同的报告顺序与相同的预算，任意两次运行必须得到逐项一致的分配结果。

硬约束：分配、报告与扣减必须在同一把锁内完成，一轮分配结果落定前不得被并发扣减插入；每轮分配是一次性快照，轮次推进后不得回改上一轮的数字；快照与活动状态完全脱钩，恢复后轮次、衰减、观察态、已分配与已用量原样回来，非法快照抛 ALLOC_SNAPSHOT_INVALID 且不改动现有数据。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发分配与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: fuzz_budget_allocator
- typeName: FuzzBudgetAllocator
