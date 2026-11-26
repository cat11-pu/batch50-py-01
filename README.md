# batch50-py-safety-c-06-p2

## 题面

安全运营这周连报三起事故：一台任务进程排查时发现环境变量里带着完整数据库口令，值班只在进程表上做了重启，口令没换，十分钟后同一容器又把口令写进临时套接字路径；另一台进程连续崩溃，监督器按固定间隔无限重拉，宿主机负载被打满，最后只能人工封机；更麻烦的是监督器状态只在内存里，升级重启后崩溃计数与隔离名单全丢，刚隔离的进程又拿到满额重启机会。问题集中在监督与凭证巡检链路，改动范围是 gsb/batch50-py-safety-c-06-p2 的 credential_watch_supervisor.py，类名 CredentialWatchSupervisor，负责维护凭证指纹名册、扫描子进程环境与文件描述符、按心跳截止判定错过、执行退避重启与崩溃环熔断，并隔离携带有效凭证的进程。所有时刻由调用方以毫秒整数传入，不做真实计时。

公开接口：CredentialWatchSupervisor(*, heartbeat_timeout_ms=5000, backoff_base_ms=1000, backoff_cap_ms=30000, crash_threshold=3, crash_window_ms=60000, max_fingerprints=256, max_findings=1024)；register_credential(credential_id, fingerprint, *, now)、rotate_credential(credential_id, fingerprint, *, now)；register_process(name, *, pid, credential_ids=(), now)、unregister_process(name, *, now)；heartbeat(name, *, now)；scan_environment(name, environ, *, now)、scan_descriptors(name, descriptors, *, now)；tick(now)；process_view(name)、process_views()；findings(name=None)；release(name, *, operator, now)；snapshot()、restore(state)、stats()。tick 返回 TickAction 元组，action 取 missed、restart、circuit_open、skipped。拒绝统一抛 CredentialWatchError(code, detail)。

故障与边界：①名称或指纹为空、pid 非正整数、credential_ids 指向未登记凭证一律 CW_INVALID_REQUEST，重名进程 CW_DUPLICATE_PROCESS，重复登记同一凭证 CW_DUPLICATE_CREDENTIAL，同一指纹绑到另一个凭证 CW_FINGERPRINT_CONFLICT；②注册成功即健康态，截止时间等于当前时刻加租期，心跳刷新截止时间并返回新截止时间，时间倒退心跳直接拒绝，迟到的旧心跳不得把截止时间往回拨；③环境扫描按变量名与值一起匹配在册的有效指纹，命中即生成 Finding，来源为 env、位置为变量名，同一进程同一指纹同一位置只记一条；④描述符扫描按 fd 与路径匹配，来源为 fd、位置为路径，同一 fd 重复扫描不重复计告警；⑤命中有效凭证的进程立即转入隔离态，原因记为 credential_leak，隔离期间不安排重启，解除隔离必须由操作者显式调用 release；⑥tick 只在时刻严格超过截止时间时判为错过，错过累计连续崩溃数，按 base×2^(n-1) 计算退避并在封顶值处停止，到期节拍才真正重启并刷新租期；⑦同一窗口内连续崩溃达到阈值转熔断态，之后任何节拍都不再重启，只能人工释放；⑧参数非法、释放非隔离进程、未登记进程上的任何操作分别按 CW_INVALID_REQUEST、CW_NOT_QUARANTINED、CW_UNKNOWN_PROCESS 拒绝；⑨凭证轮换登记新指纹并退役旧指纹，旧指纹的存量告警转为已退役，不再参与后续扫描，轮换到相同指纹是空操作返回 0，未知凭证抛 CW_UNKNOWN_CREDENTIAL；⑩指纹名册与告警台账均有硬上限，超限淘汰最旧，不得静默扩容，告警按进程、凭证、来源、位置排序；⑪快照包含 version、processes、credentials、retired、findings、counters、stats，processes 与 credentials 以名称为键，深拷贝不与内部共享，恢复时结构、版本或类型不符报 CW_SNAPSHOT_INVALID 且原状态不得改动；⑫stats 固定返回 processes、healthy、contained、circuit_open、restarts、missed、findings、rotations、releases 九项。

运维侧另点名三条：进程处于隔离态时心跳仍要记账供观测，但心跳不得让进程自动脱离隔离，也不得触发重启；心跳恰好落在截止时刻时按未超时处理；凭证轮换完成后，旧指纹不得再触发任何新的泄漏告警。

硬约束：扫描、心跳、轮换与节拍共用一把锁，同一进程同一时刻只允许重启一次，并发扫描同一环境不得重复计告警；快照恢复后退避阶梯、连续崩溃数、熔断与隔离状态、指纹名册与退役标记必须原样续上，自身重启不得清零连续崩溃数；指纹与告警条数受硬上限约束。验收运行 `python3 -m pytest -q tests`，15 条全部通过；不得修改测试、跳过用例或按固定输入写死；并发与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: credential_watch_supervisor
- typeName: CredentialWatchSupervisor
