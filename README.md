# batch50-py-safety-c-16

## 题面

隔离库上线三个月，值班同事最怕的两件事都撞上了。一件是同一份样本被七个渠道反复上报，一份内容吃掉七份配额，新样本反而进不来；另一件是一个还在取证流程里的样本被清理任务当成垃圾删了，案件的证据链当场断掉。还有一次销毁只删了实体文件、索引还在，分析师点开记录看到一份空壳。三类问题要在一周内闭环，每一次进、出、毁都要能单独解释。范围限定在 gsb/batch50-py-safety-c-16 的 sample_quarantine_vault.py，类名 SampleQuarantineVault，负责隔离样本的入库去重、引用保护、容量淘汰与墓碑式销毁。

公开接口：SampleQuarantineVault(*, quota_bytes=100000000, retention_days=30, tombstone_days=7)；admit(content_hash, *, size_bytes, source, now, priority=0, retention_days=None) -> SampleRecord；lookup(content_hash) -> dict；tag(content_hash, case_id) -> int；untag(content_hash, case_id) -> int；evict(*, needed_bytes, now) -> list[str]；purge_expired(*, now) -> list[str]；destroy(content_hash, *, actor, now) -> dict；samples()；tombstones()；capacity_report()；stats()；snapshot()；restore(state)。拒绝时抛 VaultError(code, detail)。

故障与边界：①content_hash 必须是 64 位小写十六进制，否则 VAULT_BAD_HASH；size_bytes 必须是正整数，否则 VAULT_BAD_SIZE；保留天数限 1 到 3650，否则 VAULT_BAD_RETENTION；source 不能为空，否则 VAULT_BAD_SOURCE；priority 限 0 到 9，否则 VAULT_BAD_PRIORITY；所有拒绝都要计入 denied。②到期时间按 now 加保留天数计算，输出带 +00:00 偏移的 UTC 字符串，不受主机时区影响。③同一内容哈希再次 admit 只把接收次数加一、返回既有记录，不复制实体、不占新配额、不刷新保留期。④tag 按案件登记引用，同一案件重复登记只算一次；untag 撤销后返回剩余引用数，撤销不存在的案件抛 VAULT_UNKNOWN_CASE。⑤evict 只在无案件引用的样本里按 priority 升序、入库时间先后、哈希升序挑选，凑够 needed_bytes 就停；凑不够时抛 VAULT_QUOTA_EXCEEDED 且一个都不删；needed_bytes 非正抛 VAULT_BAD_REQUEST。⑥evict 与 purge 都要记账，返回被移出的哈希列表。⑦purge_expired 只清理到期且无引用的样本，到期但仍被案件引用的样本必须留着，并继续计入 protected。⑧被引用的样本 destroy 抛 VAULT_PROTECTED；销毁成功返回含 content_hash、status、actor、destroyed_at、tombstones_until 的回执。⑨销毁后索引里不能再查到该哈希，lookup 抛 VAULT_DESTROYED，记录只能从 tombstones() 读到。⑩墓碑期内同一哈希再次上报，必须复用那条墓碑记录并把保留期重新起算，不能当成全新样本再占一份配额。⑪引用计数归零只是不再被案件占用，不等于可以立刻删，仍然要等保留期到点。⑫容量报告给出配额、已用、剩余、活跃数、受保护数与可淘汰数；统计给出 active、protected、tombstoned、admitted、duplicates、evicted、purged、destroyed、denied、total_bytes 十项。

硬约束：同一哈希的 admit、tag、untag、destroy 必须串行，配额判断与记录写入之间不得插入其它变更，淘汰要么凑够要么整体不动；快照必须与活动状态完全脱钩，恢复后到期时间、案件引用与计数原样回来，非法快照抛 VAULT_SNAPSHOT_INVALID 且不改动现有数据，进程重启后不得让快照把已销毁的样本复活。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: sample_quarantine_vault
- typeName: SampleQuarantineVault
