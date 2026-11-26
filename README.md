# batch50-py-safety-d-07

## 题面

内容抓取服务被安全组叫停：出站请求按域名解析到的是公网地址，实际连上的却是内网一台元数据服务；DNS 记录切换那半小时里，另一批请求连到了上一批已被回收的地址，抓回来的页面串了租户；还有几台机器在解析结果里混进了 IPv6，前半段看着正常，连接却落到了不该去的地方。范围是 gsb/batch50-py-safety-d-07 的 rebind_egress_guard.py，类 RebindEgressGuard，负责解析结果钉扎、连接前对端复核与按租户的出站策略；这些入口目前调用即抛 NotImplementedError，出站链路形同裸奔。

公开接口：RebindEgressGuard(*, default_ttl=60, max_pins_per_tenant=32, max_addresses_per_pin=8, reject_window=60.0, max_rejects_per_host=5, clock=None)；register_tenant(tenant, *, allow_private=False, allow_metadata=False, max_addresses=None)、policy_for(tenant)、resolve(tenant, host, addresses, ttl=None, now=None)、pin(tenant, host, addresses, ttl=None, now=None)、check_connect(tenant, host, peer_address, sni=None, cert_subject=None, now=None)、release(tenant, host)、purge(now=None)、blocked_address(address)、status()、snapshot()、restore(state)、stats()。拒绝一律抛 RebindError(code, detail)。

故障与边界：①resolve 与 pin 返回 PinRecord，addresses 去重后按数值升序，ttl 缺省取 default_ttl，expires_at 等于 created_at 加 ttl，hops 保留 CNAME 链每一跳；②同一 host 在 TTL 内重复解析且地址集合一致时复用原钉扎，created_at 与 expires_at 不变、不新增条目，stats 的 reused 加一；集合变化报 REBIND_ADDRESS_SHIFT 并计数，原钉扎保持可用；③回环、链路本地、私网、未指定、组播一律拒绝 REBIND_FORBIDDEN_ADDRESS，169.254.169.254 归元数据地址，只受 allow_metadata 控制、不受 allow_private 影响，私网只受 allow_private 控制；④空 host、空集合、非 IP 字符串报 REBIND_INVALID_REQUEST，未登记租户报 REBIND_UNKNOWN_TENANT；⑤check_connect 找不到钉扎报 REBIND_PIN_MISSING，对端在集合内 accepted 为 True、reason 为 ok，并回 pinned_addresses；⑥对端不在集合内 accepted 为 False、reason 为 peer_not_pinned 并计数，同一 host 在 reject_window 内的拒绝超过 max_rejects_per_host 报 REBIND_REJECT_LIMIT；⑦钉扎过期后 check_connect 判 pin_expired，不自动续期，必须重新 resolve；⑧release 返回删除条数，重复 release 返回 0；purge 只清过期钉扎，未过期保留，返回清理条数；⑨每租户钉扎数按 max_pins_per_tenant 封顶，单条钉扎地址数按 max_addresses_per_pin 与租户 max_addresses 取其小封顶，超出报 REBIND_CAPACITY_EXCEEDED；⑩解析结果同时含 IPv4 与 IPv6 时，任一地址落入禁止段都要按策略处理，不能只检查首选地址；⑪连接建立后对端做 NAT 重定向不在防护范围，但 check_connect 传入的 sni 与 cert_subject 必须与请求主机名逐字一致，证书主体同样逐字比对，不一致按 REBIND_SNI_MISMATCH 拒绝；⑫同一 host 被两个租户钉扎到不同地址集合时，缓存键必须含租户，不能共用一条钉扎，否则两个租户会互相顶掉对方的钉扎。

硬约束：resolve、pin、check_connect 与 release 并发时用同一把可重入锁，检查钉扎与判定对端之间不能出现被替换的窗口，同一 host 被多路并发解析只留一条钉扎、计数不翻倍；快照固定 version、tenants、pins、rejections、counters、stats 六个键，是深拷贝，restore 逐项校验结构，缺键、版本不符或类型不对报 REBIND_SNAPSHOT_INVALID 且原状态不被改动，恢复后未过期的钉扎继续有效、拒绝计数继续生效，重启不能把所有钉扎清空。status 返回 tenants、pins、addresses、rejections，四项均为条数；stats 至少含 resolved、reused、address_shifts、peer_rejections、pin_expired、released、purged、rate_limited。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；时间一律用 now 传入，缺省取当前 UTC；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: rebind_egress_guard
- typeName: RebindEgressGuard
