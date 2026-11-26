# batch50-py-safety-b-05

## 题面

机房两台边界时钟抢主，值班看到从钟时间来回跳：优先级更差的 Announce 被当成主时钟，Announce 断了十几秒还继续用旧主时钟时间戳对时。范围是 gsb/batch50-py-safety-b-05 下的 ptp_domain_warden.py，类 PtpDomainWarden，负责在单个 PTP 域内收集 Announce、按全序比较选主、处理 Announce 超时降级并按端口状态回答同步。

公开接口：PtpDomainWarden(*, domain=0, announce_timeout=3.0, max_foreign=16)；on_announce(message, *, now)；on_sync(message, *, now)；tick(now)；elected()；state()；time_trusted(*, now=None)；foreign_records()；snapshot()、restore(state)、stats()、close()。选举结果用 MasterInfo(domain, clock_identity, priority1, clock_class, clock_accuracy, variance, priority2, steps_removed, source_port, sequence)，拒绝抛 PtpError(code, detail)。now 是浮点秒。

故障与边界：①报文 domainNumber 与本地 domain 不同的 Announce 不参与比较，即使 stepsRemoved 更优也不能进候选表；②比较必须全序且可复现，顺序为 priority1、clockClass、clockAccuracy、variance、priority2、stepsRemoved、clockIdentity 字典序、sourcePort 字典序，全部更小者胜；③同一候选的重复 Announce 只刷新到达时间，不改变主时钟、不递增序号，重复计数单独累计；④较差候选仍保留在候选表里，主时钟不变；⑤主时钟切换时选举序号单调加一，首次选出为 1；⑥on_sync 只接受当前主时钟且 domain 相同的报文，其余返回 False 并计数；⑦tick 清理超过 announce_timeout 未收到 Announce 的候选，主时钟超时要降级到 listening 并重新从剩余候选里选主；⑧主时钟超时后仍沿用旧主时钟时间戳必须标记为不可信，time_trusted 返回 False；⑨快照恢复不得凭旧 Announce 直接恢复为主时钟，恢复后候选表为空、状态为 listening；⑩候选表不得超过 max_foreign，超限淘汰比较结果最差的候选；⑪close 后不再接受任何报文。

硬约束：一是候选表、主时钟与序号要在同一把锁内更新，Announce 与 tick 并发时不能选出一个已被清理的候选；二是 snapshot 固定包含 version、domain、candidates、master、sequence、counters 六个键并返回深拷贝，restore 保留选举序号与计数但清空候选表与主时钟，结构不合法抛 PTP_SNAPSHOT_INVALID 且不改动现有状态。stats 至少给出 announces、duplicates、syncs、sync_rejected、timeouts、elections、evicted、domain_dropped。

补充口径：message 至少含 domain、clock_identity、priority1、clock_class、clock_accuracy、variance、priority2、steps_removed、source_port，on_sync 另含 sequence_id。比较结果与报文到达顺序无关，同一组候选无论先后都应选出同一个。刷新到达时间不能延长已超时候选的寿命。重选后主时钟的 sequence 要大于上一任，不能回退。time_trusted 在无主时钟时也为 False，同步报文不能把已超时的主时钟重新变可信。候选表按比较顺序返回，最差的在最后，重复 Announce 只更新到达时间。on_announce 返回 True 表示报文已进入候选表或被刷新，较差候选也返回 True。首次 tick 之前状态就是 listening，只有选出主时钟才切到 master；重选事件只在主时钟身份变化时产生，tick 返回的事件名至少包括 announce_timeout 与 master_changed。close 后统计仍可读。主时钟切换时旧主时钟的候选记录保留，直到自身 Announce 超时。

验收：在包目录执行 python3 -m pytest -q tests，15 条必须全过；不得修改测试、跳过或按固定时钟写死；超时、重选与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: ptp_domain_warden
- typeName: PtpDomainWarden
