# batch50-py-safety-d-25

## 题面

平台组这周被三张单子追着跑。一张来自宿主监控：某个单元把锁定内存额度用超了，进程还在正常跑，只是 mlock 成功率和预期不符，运维照着台账算账，发现台账里同一块页被父子进程各记了一次，加起来比宿主实际锁定的还多。一张来自节点重启：重启后一批预留还挂在台账上，进程早就没了，新上来的服务申请不到额度，只能手工清账。还有一张来自特权服务：它退出之后，预留的保留池额度一直没还，普通单元持续报额度不足，直到整机重启才恢复。范围是 gsb/batch50-py-safety-d-25 的 mlock_budget_ledger.py，类名 MlockBudgetLedger，负责单元配额、两阶段预留与提交、按进程回收、保留池与主机上限。

公开接口：MlockBudgetLedger(*, host_limit=8388608, reserved_pool=1048576, reservation_ttl=60)；register_unit(unit_id, *, soft_limit, hard_limit, priority=0, privileged=False, now) -> Unit；reserve(unit_id, *, pid, start_time, exe, size, now) -> Reservation；commit(reservation_id, *, now) -> int；release(reservation_id, *, now) -> int；inherit(reservation_id, *, child_pid, child_start_time, now) -> Reservation；process_exit(pid, *, start_time, exe, now)；expire_reservations(*, now)；reclaim(*, target_free, now)；status(unit_id) -> UnitStatus；remove_unit(unit_id) -> int；units()；stats()；snapshot()；restore(state)。拒绝时抛 MlockError(code, detail)。

故障与边界：①单元重复登记抛 MLOCK_DUPLICATE_UNIT，未登记单元参与预留、查询、删除抛 MLOCK_UNKNOWN_UNIT，size 非正或不是整数抛 MLOCK_INVALID_REQUEST。②两阶段：reserve 只挂预留不动已提交额度，commit 把预留转成已提交并返回字节数，release 对已提交的预留返回释放字节数、对未提交的预留返回 0；不存在的预留标识抛 MLOCK_UNKNOWN_RESERVATION，已提交的预留再次 commit 幂等返回原字节数。③软限超出只在 status 里标 over_soft 并让 stats 的 soft_warnings 加一，仍然允许；硬限超出抛 MLOCK_HARD_LIMIT 且一个字节都不占。④普通单元的可提交总量受 host_limit 减 reserved_pool 约束，超出抛 MLOCK_HOST_LIMIT；特权单元的额度从保留池出，不计入普通配额。⑤未提交的预留在 reservation_ttl 秒后失效，expire_reservations 清理并返回被清掉的预留标识，清理顺序按到期时间升序。⑥进程退出按 pid、启动时间与可执行文件指纹三者共同匹配，匹配上才回收该进程名下的预留并返回预留标识；pid 相同但启动时间或指纹不同的新进程不得被误回收。⑦进程 fork 后子进程继承的锁定页仍归父进程那份预留，inherit 只登记归属关系，不得让同一批页在台账里重复计额度；父进程退出而子进程仍存活时，这份额度不释放。⑧特权进程退出后，它占用的保留池额度必须归还，不能永久占着让普通单元饿死。⑨回收按单元优先级从低到高，同优先级按预留创建时间从早到晚。⑩删除单元前必须额度归零，否则抛 MLOCK_UNIT_NOT_EMPTY；删掉之后返回 1，其标识可以重新登记。⑪状态给出 soft_limit、hard_limit、committed、reserved、remaining_hard 与 over_soft，remaining_hard 等于硬限减已提交减预留，小于 0 时按 0 报；Reservation 带 committed 标志与 expires_at。⑫快照保存配额表、预留到期时间与继承关系，恢复时已经过期的预留直接释放并计入 stats 的 expired；非法快照抛 MLOCK_SNAPSHOT_INVALID 且不改现状；stats 给出 units、reservations、committed_bytes、reserved_bytes、expired、reclaimed、soft_warnings 七项。

硬约束：扣减与提交在同一把锁内完成，任何时刻不得超卖，多线程并发 reserve 时总量不得超过硬限与主机上限；快照与活动状态完全脱钩，恢复后额度表、到期时间、继承关系与计数原样回来。验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: mlock_budget_ledger
- typeName: MlockBudgetLedger
