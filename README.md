# batch50-py-safety-d-10

## 题面

运维这周收到两拨告警：CA 轮换期间，一半主机报主机密钥不可信，另一半把已经被吊销的旧证书又放行了；known_hosts 批量迁移跑到一半被中断，重跑之后同一台主机出现两条互相矛盾的记录。范围是 gsb/batch50-py-safety-d-10 的 ssh_host_ca_guard.py，类 SshHostCaGuard，负责主机证书校验、CA 双活轮换、吊销版本与 known_hosts 迁移；这些入口目前调用即抛 NotImplementedError，客户端只能靠人肉比对指纹。

公开接口：SshHostCaGuard(*, max_cas=8, max_revocations=256, max_migration_entries=64, cache_ttl=300.0, clock=None)；trust_ca(name, public_key, valid_from, valid_to, now=None)、untrust_ca(name, now=None)、verify_host(host, port, certificate, now=None)、revoke(serial, ca_name, version, now=None)、revocation_version()、migrate_known_hosts(entries, now=None)、known_hosts_entries()、status()、snapshot()、restore(state)、stats()。HostCertificate 由 ca_name、serial、principals、valid_from、valid_to 构成，调用方直接构造。拒绝一律抛 HostTrustError(code, detail)。

故障与边界：①trust_ca 返回 CaRecord，valid_to 不晚于 valid_from、name 或 public_key 为空报 HOST_INVALID_REQUEST，同名重复登记报 HOST_CA_CONFLICT，CA 数量按 max_cas 封顶；②untrust_ca 注销成功返回 True 并写 retired_at，重复注销返回 False，注销后该 CA 签发的证书一律不再受信；③verify_host 依次校验 CA 受信且自身有效、证书在有效期内、主体与 host 和 port 匹配、serial 不在该 CA 的吊销清单里，全部通过返回 accepted True、reason 为 ok 并回 ca_name 与 serial；④证书过期 reason 为 certificate_expired，CA 未登记或已注销 reason 为 unknown_ca，主体对不上 reason 为 principal_mismatch；⑤主体精确匹配：不带端口的 principal 只匹配 22 端口，带端口的按 host:port 逐字匹配；一张证书带多个 principals 时只有与连接目标精确匹配的那个生效，通配符不能跨层匹配，*.example.com 不覆盖 a.b.example.com；⑥revoke 把 serial 记入对应 CA 的吊销清单并返回新的吊销版本号，版本必须单调递增，低于当前版本的调用报 HOST_REVOCATION_STALE，低版本清单不得覆盖高版本；⑦吊销清单条目按 max_revocations 封顶，超出报 HOST_CAPACITY_EXCEEDED；验证结果按主机、端口与 CA 缓存，吊销版本一变缓存立即失效；⑧migrate_known_hosts 接收 (host, port, fingerprint, key_type) 元组，返回迁移后的完整台账，按主机名与端口升序；同主机同端口同指纹跳过并计入 migration_skipped，同主机同端口不同指纹报 HOST_MIGRATION_CONFLICT，原指纹不能被覆盖；⑨迁移条目按 max_migration_entries 封顶，整批操作原子：一批里任一条超限或冲突，整批都不落库，已有台账与计数不变；⑩CA 轮换期间同一主机可能同时收到新旧两把 CA 签发的证书，二者都要能验过，吊销按各自 serial 分别判断；⑪known_hosts 迁移到一半进程退出，重启后必须认出已经迁移过的条目，不能重复追加，也不能丢掉原指纹；⑫验证结果缓存键必须含主机、端口与 CA，同一主机被不同 CA 签发的证书记录各算各的，不能互相顶掉。

硬约束：verify_host 与 revoke、untrust_ca 用同一把可重入锁，验证过程中吊销不能被插到一半，同一证书多路并发验证结论一致、计数不翻倍；快照固定 version、anchors、revocations、known_hosts、cache、counters、stats 七个键，是深拷贝，restore 逐项校验结构，缺键、版本不符或类型不对报 HOST_SNAPSHOT_INVALID 且原状态不被改动，恢复后吊销版本只能升不能降，低版本吊销清单必须被拒绝，迁移台账与各项计数继续生效。status 返回 cas、revocations、known_hosts、revocation_version，前三项为条数；stats 至少含 trusted_cas、untrusted_cas、verified、rejected_expired、rejected_unknown_ca、rejected_principal、revoked、stale_revocations、migrated、migration_skipped。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；时间一律用 now 传入，缺省取当前 UTC；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: ssh_host_ca_guard
- typeName: SshHostCaGuard
