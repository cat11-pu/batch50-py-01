# batch50-py-safety-d-02

## 题面

管理面这周被扫了两轮，安全组直接下了整改单：一台跳板机的单包授权守护进程在攻击者重放昨天抓到的授权报文时放行了两次，因为 nonce 只在内存里记了一小会儿；另一台在 NAT 出口换 IP 之后，老票据被原样拿回来继续开门，端口范围根本没再看；还有一次密钥轮换，新旧两代同时被接受，旧代次居然还能签出新票据。值班同事补了一句：失败计数按单个地址统计，攻击者换个出口刷了一晚上也没进冷却，日志里连一条聚合记录都没有。安全组要求票据、nonce、失败计数和密钥代次都能随进程重启恢复，谁在哪个端口放行过、什么时候收回，事后必须查得出来。范围是 gsb/batch50-py-safety-d-02 下的 spa_gate_guard.py，类名 SpaGateGuard，负责客户端登记、报文校验、票据签发与撤销。

公开接口：SpaGateGuard(*, window=30, skew_steps=1, max_clients=8, max_tickets=32, max_keys=4, cooldown=3, max_failures=5)；enroll(client, ports, generation, key, now)、rotate_key(generation, key, now)、verify(packet, now)、grant(packet, ttl=120, now)、revoke(ticket_id, now)、rebind(client, source, ticket_id, now)、status(client, now)、tickets(client=None, now=None)、snapshot()、restore(state)、stats()。所有拒绝统一抛 SpaError(code, detail)；status(client) 返回 active_ports、tickets、failures 三个字段。返回结构固定：enroll 给 Enrollment(client, generation, ports, enrolled_at)，rotate_key 给 KeyRecord(generation, created_at, state)，verify 给 SpaVerdict(status, client, port, nonce, generation, source)，grant 给 Ticket(ticket_id, client, port, source, nonce, generation, issued_at, expires_at, state)。

报文与摘要：packet 是 dict，含 client、port、timestamp、nonce、generation、source、mac 七个字段；mac 是把 client、port、timestamp、nonce 用竖线依次连接，以该代次密钥做 HMAC-SHA256 得到的十六进制小写摘要。

故障与边界：①enroll 对端口去重升序，重复登记报 SPA_CLIENT_EXISTS；②端口为空、越界、非整数或客户端为空报 SPA_INVALID_REQUEST；③登记的客户端与密钥代次总数封顶，超出报 SPA_CAPACITY_EXCEEDED / SPA_KEY_LIMIT；④verify 先按 source 前三段聚合的失败计数判冷却，冷却中的报文一律报 SPA_COOLDOWN；⑤未知客户端、未知代次分别报 SPA_UNKNOWN_CLIENT / SPA_UNKNOWN_GENERATION；⑥时间戳与当前步长相差超过 skew_steps 报 SPA_TIME_WINDOW，恰好一个步长必须放行；⑦端口不在登记集合报 SPA_PORT_DENIED，摘要不符报 SPA_BAD_MAC 并累加失败；⑧同一 nonce 在窗内二次出现报 SPA_REPLAY，任意时刻最多产生一张票据；⑨grant 生成 tk-1 递增票据，到期时间等于 now 加 ttl，密钥代次只读时报 SPA_KEY_READONLY；⑩revoke 让票据立即失效，status 的 active_ports 不再包含该端口；⑪票据过期由读取时惰性判定并计入 tickets_expired，now 缺省时沿用最近一次操作的时间；⑫同一客户端在 NAT 重绑后用旧票据访问，必须重新校验端口集合与时间窗，不能只凭源地址放行；报文时间戳落在两个代次重叠区时，只能用与报文代次匹配的那把密钥验，不许两把都试把重放窗口翻倍；授权到期与主动 revoke 只能产生一个终态，重复 revoke 必须幂等。

硬约束：verify 与 grant 共用一把锁推进状态，同一 nonce 任意时刻只能产生一张票据，票据计数与失败计数不得丢；快照深拷贝，恢复后登记、密钥代次、票据、nonce 窗口与失败计数都要一致，非法结构抛 SPA_SNAPSHOT_INVALID 且不改动现有状态。stats 固定返回 enrollments、keys_rotated、verifications、accepted、rejected、replays、failures、cooldown_hits、tickets_issued、tickets_revoked、tickets_expired 十一个键。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-d-02
- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: spa_gate_guard
- typeName: SpaGateGuard
- topic: 单包授权门禁：HMAC 时间窗、NAT 源地址绑定与一次性授权票据
