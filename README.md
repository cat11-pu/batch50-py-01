# batch50-py-safety-d-27

## 题面

一台边缘网关的密封密钥服务上周连爆两次问题。第一次是机房改配置后 PCR 值变了，业务侧收到的却是"对象不存在"这种含糊错误，运维照着错误码查了半天盘区；第二次更严重，一组脚本对着同一个密封对象连续试了几十次错误 PCR，服务没有任何节流，等于给人留了离线爆破的口子。另外审计还发现，服务重启后锁定记录和失败计数全部归零，上一次的锁定形同虚设。范围是 gsb/batch50-py-safety-d-27 的 tpm_sealed_store.py，类名 TpmSealedStore，负责密封对象的登记、PCR 策略校验、失败锁定与对象容量管理。

公开接口：TpmSealedStore(*, max_objects=16, max_failures=3, lock_seconds=60)；seal(name, data, *, pcr_indexes, expected, policy=None, now=None) -> SealedRecord；unseal(name, *, pcr_values, now=None) -> str；reseal(name, *, pcr_indexes=None, expected=None, policy=None, now=None) -> SealedRecord；evict(name)；hold(name) -> int；release(name) -> int；pcr_extend(index, digest, *, now=None) -> tuple；pcr_bank()；status(name)；objects()；snapshot()；restore(state)；stats()。拒绝时统一抛 SealError(code, detail)。

故障与边界：①名称为空或含空白字符报 SEAL_BAD_NAME；pcr_indexes 必须非空、取值 0 到 23、去重后按升序保存，否则报 SEAL_BAD_PCR；expected 必须恰好覆盖这些索引且摘要为 64 位小写十六进制，否则报 SEAL_BAD_EXPECTED；②同名重复密封报 SEAL_DUPLICATE，对象数达到 max_objects 报 SEAL_STORE_FULL，这类参数、容量与重复拒绝都计入 denied；记录里的 expected 以 (索引, 摘要) 升序元组保存，另含 name、version、reseal_count 与 sealed_at；③密封只登记调用方给出的最终摘要，不要求当前 PCR 等于它，密封后可继续扩展 PCR；④unseal 缺少任一索引的取值报 SEAL_BAD_PCR；摘要不符报 SEAL_POLICY_FAILED，detail 至少给出 {"index": 不匹配的索引}，并计入 unsealed_failed；⑤同一对象连续失败达到 max_failures 后进入锁定，locked_until 等于最后一次失败时刻加 lock_seconds，锁定期间即使 PCR 正确也报 SEAL_LOCKED；成功解封把该对象的失败计数清零，status 返回 pcr_indexes、version、policy、failure_count、locked、locked_until 与 held；⑥锁定到期后允许重新解封；锁定状态、失败计数与到期时间必须进快照，恢复或重启后继续生效；⑦解封结果只在内存中返回，快照只保存对象元数据，任何条目里都不得出现明文字段；⑧reseal 省略参数时沿用原 PCR 选择与策略，version 加一、reseal_count 加一；显式替换策略时把新值追加到 policy_history，首项是初次密封的策略；⑨evict 未知对象报 SEAL_NOT_FOUND，被 hold 住的对象报 SEAL_IN_USE，hold 与 release 返回当前持有计数；⑩PCR 在启动过程中会被多次扩展，密封登记的是最终摘要，扩展事件序列由 pcr_extend 单独维护供审计，校验只比对最终摘要，两者不得混用；⑪锁定到期后失败计数按每个锁定时长减一，不能一次清零，否则可以被用来做无限次尝试；⑫同一密封对象被两个调用方并发解封时必须串行，后到的一方等待而不是并行尝试，不能把失败计数一次打满。

硬约束：同一对象的 seal、unseal、reseal、evict 必须持锁串行，失败计数累加与锁定判定之间不得插入其它变更；快照必须是深拷贝，保存对象元数据、PCR 银行、统计与锁定状态，恢复后锁定继续有效，非法快照报 SEAL_SNAPSHOT_INVALID 且现有数据不动。stats 返回 sealed、duplicates、unsealed_ok、unsealed_failed、resealed、evicted、denied、locked_events。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: tpm_sealed_store
- typeName: TpmSealedStore
