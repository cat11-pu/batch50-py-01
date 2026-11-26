# batch50-py-safety-c-07

## 题面

主机防护代理上线第二天，值班同事就提了一串疑问：某挖矿样本直接从内存里执行，代理看到的命令行是 /proc/2317/fd/9，于是按普通文件路径放行了；另一台机器上运营对一个排障工具临时放行，工具随后把自己重新写了一遍继续跑，放行状态一直没撤；还有一台机器隔离了父进程，它派生出来的子进程照样把脚本跑了起来；事件日志里同一条拒绝记录刷了几百遍，真实告警被淹没。厂商要求本周内把这些口子收掉，并且每一次拦截都要能从事件记录里复盘出判据。范围是 gsb/batch50-py-safety-c-07 下的 memfd_exec_guard.py，类名 MemfdExecGuard，负责跟踪匿名内存文件的创建与密封位、判定一次 exec 的真实来源、按策略放行或隔离，并把事件落库去重。

公开接口：MemfdExecGuard(*, allow_ttl=300, default_deny=True)；on_memfd_create(*, pid, fd, inode, name, seals, now)；on_exec(*, pid, path, now)；allow(inode, *, ttl=None, now)；quarantine(inode, *, reason, now)；quarantine_process(pid, *, reason, now)；on_write(*, inode, offset, length, now)；on_clone(*, parent_pid, child_pid)；report(*, kind=None)；records()；seals_for(inode)；snapshot()、restore(state)、stats()。拒绝或越界都抛 MemfdError(code, detail)。

故障与边界：①on_memfd_create 只接受 F_SEAL_SEAL、F_SEAL_SHRINK、F_SEAL_GROW、F_SEAL_WRITE、F_SEAL_FUTURE_WRITE 五种密封名，其它名字抛 MEMFD_BAD_SEAL。②同一 inode 多次创建事件以最后一次的密封集合为准，旧状态不得残留，台账里仍只有一条记录。③缺少 F_SEAL_SEAL 的 memfd 一律拒绝执行，返回码 MEMFD_UNSEALED。④既无 F_SEAL_WRITE 也无 F_SEAL_FUTURE_WRITE 说明仍可写映射，拒绝执行，返回码 MEMFD_WRITABLE，任一个写密封存在都不算可写。⑤密封完整的 memfd 默认仍然拒绝，返回码 MEMFD_NOT_ALLOWED，只有显式 allow 之后才返回 MEMFD_ALLOWED。⑥allow 对未登记的 inode 抛 MEMFD_UNKNOWN，对密封不完整或已隔离的 inode 抛对应错误码，不得放行。⑦quarantine 之后该 inode 的 exec 返回 MEMFD_QUARANTINED，也不允许再 allow。⑧普通磁盘文件路径的 exec 返回 EXEC_FILE，不进入 memfd 台账，也不产生事件。⑨经 /proc/<pid>/fd/<n> 路径执行时必须回溯到登记过的 memfd，按原始 inode 的策略判定，不能按路径字符串直接放行。⑩放行之后若观察到该 inode 被可写映射改写，必须撤销放行、重新按未放行处理，并在日志里留下撤销原因。⑪隔离要随进程树传播：进程被隔离后，on_clone 登记的子进程执行 memfd 一律返回 MEMFD_INHERITED_BLOCK，父进程自身返回 MEMFD_PROC_QUARANTINED。⑫report 按 kind、code、inode、pid、path 去重，重复事件只累加 count 并刷新 last_at，不新增条目；放行的 exec 不建条目，同一个进程反复触发也不要重复建条目，避免日志被打爆。

硬约束：同一 inode 的创建、放行、写入、隔离等状态变更必须串行，判定时不能读到半更新的密封集合；allow 的有效期从授予时刻起算，超过有效期按未放行处理，续期只能延长不能凭空复活已撤销的放行；快照恢复后密封集合、放行标记、隔离的 inode 与进程、父子关系、事件计数原样回来，非法快照抛 MEMFD_SNAPSHOT_INVALID 且不改动现有状态。stats 返回 tracked、allowed、denied、quarantined、events 五项计数，allowed 统计放行的 exec 次数，events 为去重后的条目数。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: memfd_exec_guard
- typeName: MemfdExecGuard
