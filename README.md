# batch50-py-safety-c-03-p2

## 题面

财务月结前一天，两个租户同时把共享存储写满：一个租户的批处理往同一目录反复追加，软限早就过了却一直没人收到宽限提醒，硬限之后写入还在继续，卷被撑到 100%；另一个租户发现删文件自救也被配额模块一起拒了，只能等运维手工清盘。复盘时更麻烦：用量按卷各算各的，跨卷汇总把硬链接重复计了两次，冻结是谁触发的、什么时候解除，审计里一条都没有；宽限期到期也没有任何动作，第二天同一批任务重新提交时又从当前时刻开始算宽限，等于永远罚不下去。范围是 gsb/batch50-py-safety-c-03-p2 的 quota_freeze_arbiter.py，类 QuotaFreezeArbiter，负责按租户与卷做软硬限判定、宽限冻结、回收记账与审计；入口一调用就抛 NotImplementedError。

公开接口：QuotaFreezeArbiter(*, soft_limit=1024, hard_limit=4096, grace_seconds=3600, max_write_bytes=1024, aggregate_hard_limit=None)；register_volume(volume)、volumes()、set_quota(tenant, volume, soft_limit=..., hard_limit=...)、quota_policy(tenant, volume)、set_tenant_limit(tenant, hard_limit)、admit_write(tenant, volume, path, size, inode=None, now=None)、delete_object(tenant, volume, path, now)、truncate_object(tenant, volume, path, new_size, now)、usage(tenant)、usage_by_volume(tenant)、tenant_state(tenant, now)、freeze_tenant(tenant, reason, now)、lift_freeze(tenant, now)、audit_entries()、snapshot()、restore(state)、stats()。写入判定带 outcome、state、code、usage、remaining、grace_deadline，回收结果带 reclaimed、usage，截断结果带 action、reclaimed、decision；审计 action 取 admit、delete、truncate、freeze、release，outcome 写入取 allowed、grace、denied，回收取 reclaimed。拒绝一律抛 QuotaError(code, detail)。

故障与边界：①软限必须小于硬限且都为正，同租户同卷重复设策略报 QUOTA_POLICY_EXISTS，参数不合法报 QUOTA_POLICY_INVALID，未设置策略时 quota_policy 返回 None；②未注册的卷报 QUOTA_UNKNOWN_VOLUME；size 不是正整数或 path 不是非空字符串报 QUOTA_INVALID_REQUEST，超过 max_write_bytes 报 QUOTA_WRITE_TOO_LARGE；③写入后用量不超过软限给 allowed，remaining 等于硬限减用量；④用量严格大于软限进入 grace，宽限起点只记一次，重复超限不得重置，deadline 为起点加 grace_seconds 并写成带 +00:00 的 ISO8601 字符串，宽限内写入仍给 grace 并放行；⑤用量达到硬限后再写一律 denied，code 为 QUOTA_HARD_LIMIT，账本与用量一个字节都不许变；⑥now 不早于 deadline 时写入 denied，code 为 QUOTA_GRACE_EXPIRED，租户转入冻结；⑦冻结态下删除与截断必须放行，否则租户无法自救；删除按账本记录回收，账本里没有的路径返回 0，重复删除也返回 0，用量不得为负；⑧截断缩小按差额回收，放大走写入判定，冻结时放大同样被拒；⑨跨卷汇总按 inode 去重，同一 inode 的硬链接只计一次，usage 与 usage_by_volume 口径一致；⑩设了租户总量上限后，跨卷合计越限报 QUOTA_TENANT_LIMIT 并冻结，单卷都没超也不能放过；上限只允许调小，调小后已有用量不回滚；⑪freeze_tenant 幂等并返回 frozen，重复冻结不重复计数，冻结后写入 denied 且 code 为 QUOTA_TENANT_FROZEN；⑫lift_freeze 只对冻结态生效，用量仍不低于软限报 QUOTA_RELEASE_REFUSED，未冻结报 QUOTA_NOT_FROZEN。

硬约束：同一租户的判定与记账必须原子，并发写入不得把用量顶过硬限，denied 不许留下半条账；审计条目按 1 递增记录 action、tenant、volume、path、outcome、code、usage_after，快照固定为 version、volumes、policies、tenant_limits、objects、states、audit、stats 八个键且是深拷贝，restore 缺键或类型不符报 QUOTA_SNAPSHOT_INVALID 且原状态不动，恢复后用量、冻结态与审计序号继续可用。stats 固定为 admitted、grace_admitted、denied、written_bytes、reclaimed_bytes、grace_entered、frozen、released、audit_writes 九个键。

验收：`python3 -m pytest -q tests` 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-03-p2
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: quota_freeze_arbiter
- typeName: QuotaFreezeArbiter
- file: quota_freeze_arbiter.py
