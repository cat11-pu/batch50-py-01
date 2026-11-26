# batch50-py-safety-d-29

## 题面

推理服务的进程池最近被共享内存拖垮了三次。第一次是某个推理进程异常退出，它附加的段没人回收引用，段一直挂着，配额越用越满，新模型加载直接失败；第二次是一个段已经标了删除，但还有两个 worker 在读，配额立刻被还回去，结果新段分配出去和旧段撞在同一块逻辑配额上，账面对不上；第三次是命名空间重建之后，旧段像幽灵一样又出现在列表里，运维以为清理脚本没生效。范围是 gsb/batch50-py-safety-d-29 的 shm_quota_warden.py，类名 ShmQuotaWarden，负责 IPC 命名空间内共享内存段的配额预扣、附加引用、待删除状态与残留清理。

公开接口：ShmQuotaWarden(*, user_bytes=1048576, user_segments=8, ns_bytes=2097152, ns_segments=12)；create(namespace, key, *, owner, size, now=None) -> SegmentRecord；attach(namespace, key, pid, *, now=None) -> int；detach(namespace, key, pid, *, now=None) -> int；remove(namespace, key, *, now=None) -> int；sweep(*, stale_after=3600, now=None, whitelist=()) -> list；reap(pid, *, now=None) -> int；drop_namespace(namespace) -> int；status(namespace, key)；segments(namespace=None)；snapshot()；restore(state)；stats()。拒绝时统一抛 ShmError(code, detail)。

故障与边界：①命名空间为空报 SHM_BAD_NAMESPACE，key 必须是 0 到 2147483647 的整数，否则报 SHM_BAD_KEY，属主为空报 SHM_BAD_OWNER，大小非正整数报 SHM_BAD_SIZE，这些拒绝计入 denied；②同一命名空间同一 key 再次创建，属主相同时返回已有段且不重复占配额、不刷新大小，属主不同报 SHM_KEY_OWNED，不同命名空间同名 key 各自独立；段标识按 shm-1、shm-2 生成，记录含 namespace、key、owner、size、segment_id、state、refcount 与 created_at，segments() 按命名空间与 key 升序；③创建时按属主预扣字节与段数，超限分别报 SHM_USER_QUOTA、SHM_USER_SEGMENTS，失败不留任何水位；④按命名空间的字节与段数限额同理，超限报 SHM_NS_QUOTA、SHM_NS_SEGMENTS；⑤attach 增加引用并记录 pid 集合，返回新引用数，status 给出 state、refcount、按升序排列的 attached_pids、last_attach_at 与 size；段不存在报 SHM_NOT_FOUND，pid 非正报 SHM_BAD_PID，已标删除的段拒绝新附加并报 SHM_PENDING_DELETE；⑥detach 把引用减一，该 pid 未附加过报 SHM_NOT_ATTACHED；引用计数归零只是没人再占用，不自动删除段；⑦remove 显式标记待删除并返回剩余引用数，引用为零时立即删除；同一段重复 remove 返回当前引用数而不是报错，段彻底删除后再操作报 SHM_NOT_FOUND；⑧reap(pid) 释放该进程在所有段上的引用，返回受影响的段数，引用归零的活跃段保留在表里；⑨sweep 按最后附加时间与属主白名单清理引用为零的段，从未附加的段以创建时间作为最后附加时间，返回按命名空间与 key 升序排列的二元组列表，stale_after 非正报 SHM_BAD_STALE；⑩同一进程多次 attach 同一段时，detach 一次只能减掉一次引用，不能把计数直接清零；⑪段标记删除后仍有附加者时，配额要等最后一个 detach 才归还，不能提前释放给新段；⑫命名空间被销毁后重新创建同名空间，不得继承旧段、旧引用或旧配额水位。

硬约束：同一 key 上的 create、attach、detach、remove、reap 必须持锁串行，配额预扣与段表写入之间不得插入其它变更，超限时要么整笔成功要么整体不动；快照必须是深拷贝，保存段表、引用明细、待删除状态与配额水位，恢复后待删除段继续拒绝新附加、引用关系原样可用，非法快照报 SHM_SNAPSHOT_INVALID 且现有段表不动。stats 返回 segments、live、pending_delete、attached_refs、quota_bytes、quota_segments、created、attached、detached、removed、swept、denied，其中 removed 累计显式 remove 成功执行的次数，denied 累计参数与冲突类拒绝。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: shm_quota_warden
- typeName: ShmQuotaWarden
