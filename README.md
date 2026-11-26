# batch50-py-safety-b-07

## 题面

出口网关上周被业务投诉两次：同一租户的电商站点检查后证书主体变成网关自己的 CA，客户端直接报错；另一次是金融客户声明了固定证书，流量仍被拆开重签，对方安全团队拿着证书链找上门。运维还发现 QUIC 流量被记成已检查，实际根本没解开。更麻烦的是，租户策略与固定证书名单不在同一张表里，值班人员改了一边忘了另一边，同一域名在不同连接上得到相反结论。范围是 gsb/batch50-py-safety-b-07 的 tls_inspection_broker.py，类 InspectionBroker，负责按 SNI 与租户策略给出检查或直通决策、选择重签 CA、管理固定证书直通窗口，并在 CA 轮换时保持原子切换。

公开接口：InspectionBroker(*, default_ca="ca-root", window_seconds=900, allow_quic_downgrade=True, max_decisions=1024)；reload_ca(bundle)；ca_for_sni(sni)；set_tenant_policy(tenant, *, mode, pinned_hosts=())；decide(conn_id, *, sni, tenant, client_pinned=False, transport="tcp", now=None)；reissue_context(conn_id, now=None)；bypass_window(conn_id, *, seconds=None, now=None)；close_window(conn_id)；expire_windows(now=None)；decision_for(conn_id)；ca_ids()；ca_generation()；snapshot()、restore(state)、stats()。拒绝抛 BrokerError(code, detail)。

故障与边界：①租户未配置策略时按 inspect 处理；CA 按 SNI 后缀最长匹配，长度相同取 ca_id 字典序最小，全部未命中用 default_ca。②同一 conn_id 只允许一个决策：参数相同返回原决策，sni 或 tenant 变化报 CONN_DECISION_CONFLICT 并计数，冲突拒绝要保留首个决策，不能被后来的调用覆盖；决策对象含 conn_id、action、reason、ca_id、generation。③租户策略为 bypass 时返回 bypass、reason TENANT_BYPASS、ca_id 为空，且不得签发重签上下文；mode 只接受 inspect 与 bypass，其它值报 INVALID_REQUEST。④pinned_hosts 命中的目的地必须直通，reason PINNED_CERT，同时开一个 window_seconds 的直通窗口，到期时刻为 now 加 window_seconds；窗口只对该连接生效，其它连接命中同一主机仍按策略重新判断。⑤窗口到期由 expire_windows 收回并计数，该连接的决策随之清空，再次决策必须按当前策略重新计算。⑥客户端自报固定证书而策略要求检查时，仍要直通并上报事件，不能静默重签。⑦reissue_context 只对 inspect 决策有效，否则报 NO_INSPECTION_DECISION；重签证书的 SAN 必须覆盖 SNI；SAN 为空或缺少 SNI 时不得签发上下文，按决策不合法处理。⑧同一连接重复取重签上下文必须幂等，serial 不变，计数只加一次。⑨reload_ca 返回新代次并原子切换，初始代次为 1：新代次立即生效，旧代次保留一个重叠期；非法 bundle 报 CA_BUNDLE_INVALID，旧配置与已有决策都不受影响；轮换过程中读侧要么看到旧映射，要么看到新映射，不能混用两代 CA。⑩ca_ids 按活跃、重叠顺序返回；连续两次轮换后第一代被回收并计数。⑪QUIC 或 UDP 连接无法检查，允许降级时返回 downgrade，否则返回 reject，绝不能当作已检查放行。⑫决策表达到 max_decisions 报 DECISION_CAPACITY_EXCEEDED；空 conn_id、空 sni、未知 transport 报 INVALID_REQUEST，参数校验在查表之前完成，失败不占用决策名额；快照含 version、cas、tenants、decisions、windows、stats 六个顶层键并深拷贝，非法结构报 BROKER_SNAPSHOT_INVALID 且原状态不变。

硬约束：CA 轮换与决策写入必须原子，读侧不能看到半套映射；决策缓存、直通窗口与租户策略要能持久化，重启恢复后同一连接不重复决策；每条连接至多一个决策、容量硬顶。stats 返回 decisions、inspected、bypassed、downgraded、rejected、windows_open、windows_expired、reloads、conflicts、ca_retired、reissues。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: tls_inspection_broker
- typeName: InspectionBroker
