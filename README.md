# batch50-py-safety-d-15

## 题面

对象存储巡检连报三单：桶策略允许公共读但 ACL 私有，台账各取允许即判公开；另一个桶 HEAD 200、GET 403 被写成可下载；同一桶两个账号登记在不同区域，复检重复出结论。范围是 gsb/batch50-py-safety-d-15 的 bucket_exposure_scanner.py，类 BucketExposureScanner。

接口：BucketExposureScanner(*, max_buckets, probe_per_minute, cooldown_seconds, rescan_interval, prober)；register(bucket, *, region, account, acl, policy)；evaluate_acl(bucket, *, region, acl, policy)；probe_anonymous(bucket, region, now)；confirm(bucket, region, now)；rescan(bucket, region, now)；拒绝抛 ExposureError(code, detail)。

边界：①ACL 与策略合并，显式拒绝优先。②公共读写分开判定。③桶名 3-63 位小写字母数字连字符，否则 INVALID_BUCKET。④超 max_buckets 抛 CAPACITY_EXCEEDED。⑤403 clean、404 missing、网络错误 PROBE_FAILED。⑥5xx 进冷却，期内再探 COOLDOWN_ACTIVE。⑦confirm 需可复现匿名读取，否则 NOT_REPRODUCIBLE。⑧HEAD 200、GET 403 按 GET 判，不算公开可读。⑨同桶不同区按桶名+区域去重。⑩策略变化失效缓存；探测超额 PROBE_RATE_LIMITED。⑪rescan 周期内用缓存，无证据转 fixed。

硬约束：状态迁移 RLock 原子；快照深拷贝台账、水位与统计，非法 SNAPSHOT_INVALID；stats 含 buckets、probes、not_found、failures、cooldowns。

验收：`python3 -m pytest -q tests` 十五条全过；不改测试、不跳过、不写死；并发与重启自验；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- module: bucket_exposure_scanner
- typeName: BucketExposureScanner
