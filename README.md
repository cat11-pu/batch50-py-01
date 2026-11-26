# batch50-py-safety-c-10

## 题面

备份系统上个月出了两次事故：某个恢复点在保留期内被客户端以管理员身份删掉了锁文件，平台把它当成正常释放，第二天就被新备份覆盖；某仓库的金丝雀文件被改写了整整两周才被发现，期间所有备份都不可信。另外还有一次两个清理任务同时抢同一个恢复点的释放权，两边都回了成功，账对不上。范围是 gsb/batch50-py-safety-c-10 下的 backup_immutability_warden.py，类名 BackupImmutabilityWarden，负责锁住恢复点与最短保留期、单调延长、金丝雀冻结以及恢复前的完整性校验。

公开接口：BackupImmutabilityWarden(*, quota_gb=1000.0)；register_canary(path, digest)；lock(restore_point, *, size_gb, min_retention_days, now)；extend(restore_point, *, extra_days, now)；release(restore_point, *, actor, now)；on_lock_file_missing(restore_point, *, actor, now)；check_canary(path, *, observed_digest, now)；verify_restore(restore_point, *, total_chunks, ok_chunks, now)；can_backup()；restore_allowed(restore_point)；retention(restore_point, *, now)；locks()；snapshot()、restore(state)、stats()。拒绝时抛 WardenError(code, detail)。

故障与边界：①lock 的最短保留期必须是 1 到 3650 之间的整数天，越界抛 WARDEN_BAD_RETENTION；size_gb 必须为正数，否则抛 WARDEN_BAD_SIZE；重复锁同一个恢复点抛 WARDEN_ALREADY_LOCKED。②到期时间按 locked_at 加天数计算，输出带 +00:00 偏移的 UTC 字符串，不得受主机本地时区影响。③retention 返回 restore_point、expires_at 与 remaining_days，按传入的 now 计算剩余天数，已过期时给出负数但锁仍在台账里。④extend 只能让到期时间往后走，额外天数必须为正，试图缩小保留期抛 WARDEN_LOCK_SHRINK；对未加锁或已释放的恢复点抛 WARDEN_NOT_LOCKED；extensions 逐次累加。⑤延长会把该恢复点计入存储配额，超过 quota_gb 时拒绝延长并保持原到期时间，不得为了腾空间静默删除任何旧恢复点。⑥保留期内 release 抛 WARDEN_LOCK_HELD，到期后 release 成功一次并返回含 restore_point、actor、status、released_at 的回执，第二次抛 WARDEN_ALREADY_RELEASED。⑦同一恢复点被两个任务同时申请释放时只能有一个成功，另一个必须收到拒绝，回执不得写出两份。⑧备份客户端以管理员身份删除锁文件时，on_lock_file_missing 必须按篡改处理：冻结整个仓库并抛 WARDEN_TAMPER_DETECTED，不得当成正常释放。⑨register_canary 登记仓库内金丝雀路径与摘要；check_canary 对未登记路径抛 WARDEN_CANARY_UNKNOWN，摘要一致返回 path、ok、frozen 三个字段且 ok 为真，摘要不一致时冻结仓库、can_backup 返回 False，冻结后新的 lock 一律抛 WARDEN_REPO_FROZEN。⑩verify_restore 要求 total_chunks 至少为 1 且 ok_chunks 介于 0 与 total 之间，否则抛 WARDEN_BAD_REQUEST；校验不全时恢复点状态为 unusable、restore_allowed 返回 False，全部通过时状态为 verified 且允许恢复。⑪锁台账持久化：重启后按登记的到期时间计算剩余时间，不得从头重新计时；快照恢复后锁、到期时间、金丝雀摘要、冻结标记、校验结论与计数原样回来，非法快照抛 WARDEN_SNAPSHOT_INVALID 且不改动现有数据。stats 返回 locked、extended、released、frozen、integrity_failed 五项计数。

硬约束：同一恢复点的 lock、extend、release 必须串行，配额计算、释放判定与回执写入之间不得插入其它变更，配额不足时宁可拒绝也不得动别的恢复点；快照必须与活动状态完全脱钩，恢复后的剩余保留时间不得被重置，已释放的恢复点不得借快照回到锁定状态。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: backup_immutability_warden
- typeName: BackupImmutabilityWarden
