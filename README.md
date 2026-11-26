# batch50-py-safety-c-10-p2

## 题面

擦除机房这批退役盘又出了两次事故：一次是两台执行机同时领到同一段扇区，两边都在写，校验值对不上，整块盘只能返厂；另一次是执行机擦到一半掉线，重连之后调度器把整段区间当成新任务重新下发，前面擦好的几个小时全白做；还有人手工取消了一个作业又马上重新提交同一区间，结果新作业继承了旧作业的进度，漏擦了一大片。这三个问题叠在一起，每周至少有一次要找执行机手工补擦。范围是 gsb/batch50-py-safety-c-10-p2 下的 wipe_job_scheduler.py，类 WipeJobScheduler，负责按设备区间切分作业、租约领取、分片进度落盘与掉线后的断点续做。

公开接口：WipeJobScheduler(*, lease_ms=30000)；register_device(name, *, blocks)、set_device_online(name, *, online)；submit(*, device, start, end, shard_blocks) 返回作业号；claim(worker, *, now, lease_ms=None) 返回 Lease（lease_id、job_id、shard_index、start、end、expires_at）或 None；report_progress(lease_id, done_blocks, *, now) 返回 completed、done_blocks、remaining；resume(job_id, *, now) 返回重新入队的分片数；cancel(job_id) 返回回收的分片数；status(job_id)；shards(job_id)；leases()；snapshot、restore、stats。拒绝时抛 WipeError(code, detail)。

故障与边界：①设备名非空、块数为正，重名报 WIPE_DUPLICATE_DEVICE，非法报 WIPE_INVALID_REQUEST，未知设备报 WIPE_UNKNOWN_DEVICE；②区间的 start 必须小于 end 且不能越过设备块数，分片大小必须为正，否则报 WIPE_INVALID_REQUEST；③同一设备上与活跃作业重叠的区间报 WIPE_RANGE_CONFLICT，首尾相接不算重叠；④作业按区间等分成 shard_blocks 大小的分片，最后一片可以不足，编号从 0 开始；⑤claim 按作业号升序、片号升序取第一个待领取分片，同一执行方已有未到期租约时报 WIPE_LEASE_ACTIVE，没有可领的返回 None；⑥report_progress 只接受本次租约，租约过期或已作废报 WIPE_LEASE_LOST；进度回退报 WIPE_PROGRESS_REGRESS 且保存值不变，报告成功会顺延租约；⑦进度达到分片长度即标记完成并计入作业进度，全部分片完成时作业转 complete；⑧租约过期的分片由 resume 退回待领取，已有进度保留，已完成的分片不得重新入队；⑨cancel 回收所有未完成分片并作废相关租约，已取消的再取消返回 0，已完成作业取消报 WIPE_JOB_COMPLETE；⑩设备掉线时该设备上的未完成租约全部分片退回待领取，掉线期间 claim 不得下发，设备重新上线后可以继续领取；⑪取消后再次提交同一区间必须视为新作业，不能继承旧作业任何进度；⑫快照含 version、devices、jobs、shards、leases、counters、next_job、next_lease，jobs 以作业号为键，快照与内部状态不共享，restore 结构非法报 WIPE_SNAPSHOT_INVALID 且不动现有数据。

硬约束：并发 claim 不得把同一个分片发给两个执行方，租约编号与分片归属必须一一对应；进度按分片持久化，调度器重启后租约到期判定与已完成标记必须原样接续，已完成的区间不得重擦。只做本地实现，不得改测试、跳过或按固定输入写死；并发与重启自行验证。验收运行 python3 -m pytest -q tests，15 条全部通过。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: wipe_job_scheduler
- typeName: WipeJobScheduler
