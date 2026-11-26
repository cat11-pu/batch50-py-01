# batch50-py-safety-d-04

## 题面

反向代理这周在凌晨被打了两枪：一台边缘节点因为缓存的 OCSP 响应早已过期还在继续回装订数据，客户端直接握手失败，日志里只剩一行验签错误；另一台更麻烦，must-staple 的证书拿不到有效响应，进程居然回了一个空的装订扩展，握手当时没报错，业务侧过了半小时才全部访问不来；还有一次中间证书链被整体换掉，缓存里旧链的响应被搬到了新链上，吊销状态整个错位。运维给的口径是：刷新与读取不能卡在网络上，同一张证书同一时刻只允许一个刷新在途，重启之后剩余有效期和刷新时间必须重新算过。值班同事还翻出一笔旧账：有次批量刷新集体失败，退避没有上限，重试直接把上游响应器打成了半瘫，这次也要一并收住。范围是 gsb/batch50-py-safety-d-04 下的 ocsp_staple_cache.py，类名 OcspStapleCache，负责每张站点证书的响应缓存、刷新租约与吊销传播。

公开接口：OcspStapleCache(*, max_bytes=65536, max_fingerprints=16, refresh_ratio=0.75, retry_backoff=30, lease_ttl=10)；register(site, fingerprint, issuer, serial, must_staple=False, now)、get_staple(site, now)、acquire_refresh(site, now)、release_refresh(site, now)、refresh(site, body, this_update, next_update, status="good", serial=None, issuer=None, signature_ok=True, lease=None, now=None)、invalidate(fingerprint, issuer=None, status="revoked", now)、mark_revoked(issuer, serial, now)、status(site=None)、sweep(now)、snapshot()、restore(state)、stats()。所有拒绝统一抛 StapleError(code, detail)。status(site) 返回 available、body_size、in_flight、issuer 四个字段，status() 不带参数时返回 sites、cached、revoked、in_flight、bytes 五个聚合字段。返回结构固定：register 给 CertRecord(site, fingerprint, issuer, serial, must_staple, registered_at)，get_staple 给 StapleView(site, available, body, state, this_update, next_update, issuer)，acquire_refresh 给 RefreshLease(site, fingerprint, issuer, acquired_at, expires_at, lease_id)，refresh 给 RefreshResult(site, fingerprint, issuer, state, body_size, this_update, next_update)，sweep 给 SweepReport(due, expired, evicted)。

故障与边界：①register 校验站点、指纹、签发者与序列号，重复站点报 STAPLE_SITE_EXISTS；②未知站点报 STAPLE_UNKNOWN_SITE，普通证书未命中返回 available 为假、state 为 empty；③must-staple 证书没有有效响应时报 MUST_STAPLE_UNAVAILABLE，不得回空装订；④refresh 原样缓存响应字节，state 取响应状态，body_size 等于字节数；⑤序列号或签发者与登记不符，分别报 STAPLE_SERIAL_MISMATCH / STAPLE_ISSUER_MISMATCH；⑥签名校验失败报 STAPLE_BAD_SIGNATURE，this_update 不小于 next_update 时报 STAPLE_WINDOW_INVALID；⑦超过 next_update 后立即停止对外提供，读到的 state 为 expired 且 body 为空；⑧刷新租约独占，重复获取或未持租约刷新报 REFRESH_IN_PROGRESS，租约按 lease_ttl 失效；⑨响应字节与指纹数量双封顶，超出报 STAPLE_CAPACITY_EXCEEDED / STAPLE_FINGERPRINT_LIMIT；⑩invalidate 按指纹命中全部站点并返回计数，mark_revoked 必须签发者与序列号同时匹配才计数；⑪sweep 在 next_update 之前按 refresh_ratio 提前报出待刷新条目，过期条目计入 expired；⑫同一证书被两张不同中间证书链引用时，响应不能跨签发者复用；系统时钟回拨导致 next_update 看似仍在未来时，必须结合本地单调时间判定响应是否可信；吊销响应到达后，正在进行的握手必须在下一次读取装订数据时看到 revoked，而不是等缓存自然过期。

硬约束：刷新与读取共用一把 threading.RLock 保护缓存与租约迁移，读路径不得阻塞在网络请求上，同一证书任意时刻只允许一个在途刷新；快照深拷贝，含 version、sites、cache、leases、counters 五个键，恢复后按剩余有效期重算刷新时间，非法结构抛 STAPLE_SNAPSHOT_INVALID 且不改动现有状态。stats 固定返回 registrations、refreshes、cache_hits、cache_misses、invalidated、revoked、sweeps、refresh_failures 八个键。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-d-04
- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: ocsp_staple_cache
- typeName: OcspStapleCache
- topic: 反向代理证书 OCSP 装订缓存：nextUpdate 驱动刷新、must-staple 强制与吊销传播
