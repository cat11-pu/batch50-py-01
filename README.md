# batch50-py-safety-d-09

## 题面

证书签发入口这周出了四类工单：验证重试次数打满，证书始终没签出来，订单却一直挂在 pending；同一个域名下两个订单先后提交，后一个直接复用了前一个的验证结果；DNS-01 在 TXT 记录还没传播完就被判失败；账户密钥轮换以后，旧订单的授权还当成有效继续用。范围是 gsb/batch50-py-safety-d-09 的 acme_challenge_gate.py，类 AcmeChallengeGate，负责订单、授权、挑战校验与签发状态机；这些入口目前调用即抛 NotImplementedError，签发入口等于关闭。

公开接口：AcmeChallengeGate(*, max_orders_per_account=8, max_attempts=3, order_ttl=3600, propagation_delay=30.0, clock=None)；register_account(account_id, thumbprint, now=None)、rotate_account_key(account_id, thumbprint, now=None)、account_for(account_id)、new_order(account_id, identifiers, now=None)、authorize(order_id, identifier, challenge_type="http-01", token=None, now=None)、validate(order_id, identifier, nonce, value, now=None)、finalize(order_id, csr, now=None)、revoke(serial, reason=None, now=None)、order_status(order_id)、authorization_for(order_id, identifier)、status()、snapshot()、restore(state)、stats()。拒绝一律抛 AcmeError(code, detail)。

故障与边界：①register_account 返回 AccountRecord，thumbprint 原样保存，重复登记同一 account_id 报 ACME_INVALID_REQUEST，账号不存在报 ACME_UNKNOWN_ACCOUNT；②rotate_account_key 换掉 thumbprint 并写 rotated_at，之后 HTTP-01 校验值按新 thumbprint 计算；③new_order 返回 OrderRecord，identifiers 去重后按字典序保存，订单从 pending 起步，每个标识生成一条 AuthorizationRecord，空列表或含重复标识报 ACME_INVALID_REQUEST，订单数按 max_orders_per_account 封顶、超出报 ACME_CAPACITY_EXCEEDED；④authorize 为订单内标识发放 challenge_type 默认 http-01 的令牌，token 至少 32 位，同一订单同一标识只发放一次，重复调用报 ACME_TOKEN_REUSED，标识不在订单内报 ACME_UNKNOWN_AUTHORIZATION；⑤HTTP-01 校验值为 token 拼一个点再拼账户 thumbprint，逐字一致才算通过，通过后授权转 valid 且不计入 attempts，全部授权 valid 后订单转 ready；⑥校验失败不改终态但 attempts 加一，next_at 按指数退避给出，第一次为 now 加 2 秒、之后每次翻倍；失败使 attempts 达到 max_attempts 的那一次直接抛 ACME_ATTEMPTS_EXHAUSTED，整单与对应授权转 invalid；⑦nonce 一次性，在校验入口最先校验并立即消费，失败也消耗，同一 nonce 再提交报 ACME_NONCE_REPLAY；⑧finalize 要求全部授权 valid，否则报 ACME_ORDER_NOT_READY，成功返回 CertificateRecord、serial 为 40 位小写十六进制，订单转 valid 且此后只读，再 finalize 报 ACME_ORDER_IMMUTABLE；⑨revoke 按 serial 吊销，成功返回 True、写上 revoked_at 并把订单转 invalid，重复吊销返回 False，未登记 serial 报 ACME_UNKNOWN_CERTIFICATE；⑩同一标识同时存在两个订单时，挑战令牌与验证结果必须按订单隔离，不能共用一条；⑪DNS-01 的 TXT 记录在传播窗口内旧值仍可见，必须确认新值出现再判通过，不能首次查询没看到新值就判失败；⑫账户密钥轮换后，旧订单的授权不自动延续，必须按新密钥重新验证。

硬约束：validate 与 finalize 按订单用同一把可重入锁串行，同一 nonce 被多路并发提交只能有一个成功，其余报 ACME_NONCE_REPLAY，订单状态不能出现一半 valid 一半 pending；快照固定 version、accounts、orders、authorizations、certificates、counters、stats 七个键，是深拷贝，restore 逐项校验结构，缺键、版本不符或类型不对报 ACME_SNAPSHOT_INVALID 且原状态不被改动，恢复后订单状态、令牌、已用 nonce 与失败计数继续生效，重启不能把 nonce 清空成可重放。status 返回 accounts、orders、authorizations、certificates，四项均为条数；stats 至少含 registered、orders_created、authorized、validated、failed、exhausted、finalized、revoked、rotated、nonce_replays。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；时间一律用 now 传入，缺省取当前 UTC；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: acme_challenge_gate
- typeName: AcmeChallengeGate
