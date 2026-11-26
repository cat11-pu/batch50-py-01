# batch50-py-safety-d-30

## 题面

监控平台上周被性能事件采集反咬了一口。一个新上线的采集器以特权身份打开了内核地址采样，运维按例把 paranoid 级别调高，结果老采集还一直在采，直到进程自己退出才停；另一个问题是滚动发布时子进程 fork 出来继承了父进程的事件，配额按请求方各记一遍，同一个被监控任务把整个 cgroup 的额度吃光；还有一次撤销采集只改了状态，描述符没回收，采集器继续读，事后审计里连谁在什么时候开的都对不上。范围是 gsb/batch50-py-safety-d-30 的 perf_access_governor.py，类名 PerfAccessGovernor，负责性能事件的权限分级、按 cgroup 配额、描述符引用与撤销审计。

公开接口：PerfAccessGovernor(*, paranoid=2, max_events_per_cgroup=4, privilege_pool=2, privilege_ttl=60)；set_paranoid(level)；add_blacklist(event_type) -> int；add_whitelist(event_type) -> int；request(*, requester, event_type, cgroup, target_pid=None, target_cpu=None, kernel=False, privileged=False, now=None) -> RequestRecord；open(request_id, *, now=None) -> int；close(fd, *, now=None) -> dict；revoke(*, requester=None, cgroup=None, event_type=None, now=None) -> int；review(*, now=None) -> dict；inherit(parent_pid, child_pid, *, now=None) -> int；audit(*, now=None) -> list；active()；status()；snapshot()；restore(state)；stats()。拒绝时统一抛 PerfAccessError(code, detail)。

故障与边界：①requester、event_type、cgroup 不能为空，target_pid 与 target_cpu 必须二选一，pid 为正整数、cpu 为非负整数，否则报 PERF_BAD_REQUEST 或 PERF_BAD_TARGET；paranoid 只接受 0 到 4，越界报 PERF_BAD_PARANOID，这些拒绝计入 denied；请求标识按 req-1、req-2 生成，created_at 取调用时刻，记录保留 level、kernel 与 privileged；②黑名单优先于白名单与特权，命中即报 PERF_BLACKLISTED 并计入 blacklisted，任何级别都不放行，add_blacklist 与 add_whitelist 返回当前名单条数；③paranoid 为 4 时拒绝全部请求，2 起拒绝 kernel=True 的内核地址采样，3 起拒绝 cpu 维度采集，白名单事件在 cpu 维度放宽一级；④特权请求按低一级的 paranoid 判定，占用独立保留池，池满报 PERF_PRIVILEGE_EXHAUSTED，授权记录带 expires_at；⑤同一 cgroup 同时存在的已批准请求有上限，超出报 PERF_QUOTA_EXCEEDED，close 之后名额释放；⑥open 从 3 开始分配描述符，同一 cgroup 同一监控目标复用同一描述符并增加引用，close 返回 fd、refcount、closed，引用减到零才算真正关闭，active 每条含 fd、cgroup、target_pid、target_cpu 与 refcount；⑦open 未知请求报 PERF_NOT_FOUND，已关闭或已撤销的请求再 open 报 PERF_REQUEST_CLOSED，close 未知描述符报 PERF_BAD_FD；⑧revoke 按请求方、cgroup、事件类型的组合撤销，立即关闭对应采集并让描述符失效，返回撤销的请求数；⑨review 按 expires_at 处理特权到期并复核当前 paranoid，返回 privilege_expired、closed、degraded，审计每条含 action、requester、event_type、cgroup 且只记元数据，不得写入内核地址；⑩采集者降权后，已经打开的事件必须在下一次复核时关闭，不能等进程退出才停；⑪同一 pid 在 fork 后子进程继承事件，配额要按实际被监控任务归属，不能按请求方重复计；⑫paranoid 提高后新请求立即拒绝，已经打开的采集保留到复核周期，期间记为降级宽限，status 返回当前 paranoid 与活动采集概览。

硬约束：配额扣减、描述符引用与撤销必须用同一把可重入锁串行，批准与名额扣减之间不得插入其它变更，撤销要么全部生效要么不动；快照必须是深拷贝，保存 paranoid、黑名单白名单、配额表、描述符与活动采集，恢复后描述符继续可用并按当前 paranoid 重新校验，非法快照报 PERF_SNAPSHOT_INVALID 且活动集不动。stats 返回 granted、denied、opened、closed、revoked、quota_denied、privilege_denied、review_closed、blacklisted。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: perf_access_governor
- typeName: PerfAccessGovernor
