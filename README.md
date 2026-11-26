# batch50-py-safety-d-17

## 题面

盲打跨站脚本这块最近很乱：同一处评论区反复收到同一个回连，值班同学当成新线索重复开了三张单；有个载荷租约早就过期，回调却被算到上周那个任务头上；还有一条明显伪造的回连，签名对不上却照样进了结论表。范围是 gsb/batch50-py-safety-d-17 的 xss_callback_correlator.py，类 XssCallbackCorrelator，负责给注入点下发载荷、接收回连并给出关联结论。

公开接口：XssCallbackCorrelator(*, secret="corr-secret", max_payloads=200, default_ttl=1800, per_source_limit=10, per_payload_limit=3, clock=None)；issue_payload(target, injection_point, *, tenant="t1", ttl=None, now=None)、handle_callback(payload_id, *, signature, source_ip, ua, now=None)、lookup(payload_id)、expire(now=None)、revoke_payload(payload_id, reason)、list_payloads(target=None)、set_rate_limit(*, per_source=None, per_payload=None)、report()、snapshot()、restore(state)；异常统一抛 CallbackError(code, detail)。

故障与边界：①载荷标识形如 PL- 加 12 位十六进制，签名取 sha256("secret:payload_id") 的前 16 位十六进制；②时间统一 ISO-8601 带 +00:00，到期时间等于签发时间加租约秒数；③同一租户同一目标同一注入点在租约未过期时重复下发必须复用原载荷，复用计数加一而不是新发；④同一载荷同来源 IP 同 UA 的重复回连只记一次，重复计数加一，结论沿用首次；⑤同一载荷第一次回连结论为 confirmed，第二个不同来源的回连结论为 probable；⑥载荷标识查不到抛 CALLBACK_UNKNOWN_PAYLOAD，已撤销载荷抛 CALLBACK_PAYLOAD_REVOKED；⑦签名对不上抛 CALLBACK_SIGNATURE_INVALID 并计入滥用计数；⑧超过来源或载荷维度的回连限额抛 CALLBACK_RATE_LIMITED 并计入 throttled；⑨活动载荷数超过 max_payloads 抛 CALLBACK_CAPACITY_EXCEEDED；⑩expire 把到期载荷置 expired 并返回条数，对已过期载荷的回连结论记 orphan；⑪空目标、空注入点、空租户抛 CALLBACK_INVALID_REQUEST；⑫同一载荷被注入两个不同租户的页面时，回调归属按租约记录的租户判定而不能按来源 IP 推断；回调正好落在租约到期时刻的，按载荷签发时间与租约长度判定归属，不能只看当前时间。

report() 返回 issued、reused、callbacks、duplicates、throttled、expired、revoked、abuse、active 与 conclusions（confirmed/probable/orphan 三个计数）；list_payloads 按签发时间与载荷标识升序排列，可按目标过滤。回调内容只保留来源 IP、UA、接收时间与判定字段，不存 Cookie 与页面正文；载荷与回调表都有容量上限。

载荷台账要能回答三件事：这个载荷是哪个租户在什么时候对哪个注入点下发的、这条回连首次出现在哪个来源、结论为什么是 confirmed 而不是 probable；台账只追加不删记录，撤销与过期都只是状态位。同一注入点再次下发时，如果原载荷已被撤销就不能复活，必须新发一条并换上新的签名。

硬约束：issue 与 handle 的状态迁移共用同一把 threading.RLock，同一载荷的并发回连不得产生两条事件，复用判定与计数更新必须原子；快照返回 version、leases、events、dedupe、counters、seq 六个键且为深拷贝，restore 遇缺键或类型不符抛 CALLBACK_SNAPSHOT_INVALID 且不改动现有状态。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: xss_callback_correlator
- typeName: XssCallbackCorrelator
- file: xss_callback_correlator.py
