# batch50-py-safety-d-12

## 题面

依赖准入连出两起事故：内部前缀包在公共源出现同名高版本，被按最新版拉走；另一包维护者三天前换人，流水线照样升级；锁文件地址与元数据对不上，构建仍通过。范围是 gsb/batch50-py-safety-d-12 的 dependency_confusion_guard.py，类 DependencyConfusionGuard。

接口：DependencyConfusionGuard(*, internal_prefix, similarity_threshold, max_quarantine)；add_source(name, *, priority, kind)；ingest(metadata)；evaluate(package, *, ecosystem, version, lock_source, now)；resolve_batch(requests, *, now)；quarantine(package, *, version, reason, ttl, now)；拒绝抛 DependencyGuardError(code, detail)。

边界：①内部前缀包只认私有源，无元数据包直接拦截。②包名去分隔符并归一形似字符后比对，超阈值抛 TYPOSQUAT，无内部包时相似度 0。③允许清单跳过相似度，仍受源与发布者约束。④发布者宽限期内变更降 confirm。⑤同名多源按源优先级，不取最高版本。⑥锁文件完整 URL 与元数据不符以锁文件为准拒绝。⑦隔离区按包版本去重，release 摘除，超上限 CAPACITY_EXCEEDED，到期 purge_expired 清。⑧裁决按包名与版本缓存，发布者或策略变即失效。⑨批量按依赖序，任一拒绝整批 BATCH_REJECTED 并指出根因包。⑩私有源缺失时内部前缀包直接拒绝；西里尔拉丁混排先归一。

硬约束：缓存与裁决 RLock 互斥，隔离区变更串行；批量同层按名称升序；策略变更递增 policy_version 并清空缓存；快照深拷贝台账与统计，非法抛 SNAPSHOT_INVALID 原状态不变。stats 含 evaluations、quarantined。

验收：`python3 -m pytest -q tests` 十五条全过；不改测试、不跳过、不写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- module: dependency_confusion_guard
- typeName: DependencyConfusionGuard
