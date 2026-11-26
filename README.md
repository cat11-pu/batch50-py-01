# batch50-py-safety-d-11

## 题面

域名组连收三张单子：CNAME 仍指向下线的托管服务，被第三方占位；另一域名 NXDOMAIN 却被服务指纹判成可利用；复检窗口内反复入表，重启即丢证据与水印。范围是 gsb/batch50-py-safety-d-11 的 dangling_cname_guard.py，类 DanglingCnameGuard。

接口：DanglingCnameGuard(*, max_conclusions, max_evidence, scan_rate, resolver)；register_zone(zone, records, *, owner, owned_hosts=())；scan_domain(domain)；fingerprint(service, *, suffixes=None, markers=None)；confirm(domain, *, verdict="confirmed")；rescan(domain)；拒绝抛 TakeoverError(code, detail)。

边界：①域名小写去尾点，越界 ZONE_INVALID。②未登记 DOMAIN_UNKNOWN；DNS_TIMEOUT、SERVFAIL 分码。③NXDOMAIN、未认领、错误页留证，其余 clean。④指纹命中且非 owned_hosts 才未认领，服务名入 service。⑤同服务商仍占用者不判悬空。⑥A+CNAME 并存按 CNAME 判，批次不中断。⑦指纹更新重算结论。⑧confirm 仅 candidate，非法 verdict/状态抛 VERDICT_INVALID、STATE_INVALID。⑨周期内 rescan 用缓存计 cached，超期重查，无证据转 fixed。⑩超额 SCAN_RATE_LIMITED，超限 CAPACITY_EXCEEDED，证据截断，未过 TTL 不改判。

硬约束：状态迁移在 RLock 内原子，同一域名一条结论；扫描升序且容量、限速同时生效；可利用仅 confirmed；快照深拷贝结论、统计，非法抛 SNAPSHOT_INVALID 状态不变。stats 含 domains、failed。

验收：`python3 -m pytest -q tests` 十五条全过；不改测试、不跳过、不写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- module: dangling_cname_guard
- typeName: DanglingCnameGuard
