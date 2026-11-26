# batch50-py-safety-a-02

## 题面

JARM 上线第二天，某 RP 把整批回跳判成无效响应，日志里能看到同一个 state 被补偿接口放行了两次；周末密钥轮换后另一家 RP 又报验签全挂，两家登录成功率从九成九掉到七成，值班只能先回退到 query 传参顶着。范围是 gsb/batch50-py-safety-a-02 的 jarm_response_signer.py，类 JarmResponseSigner，负责把授权结果按客户端登记算法与密钥版本封成 JWT 安全响应，写入 iss、aud、exp 与 state，并在回跳前核销 state；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：JarmResponseSigner(*, state_ttl=300)；register_client(client_id, tenant, algorithms, kid, secret, now)、client_keys(client_id)、rotate_client_key(client_id, kid, secret, now)、revoke_key(client_id, kid)、sign(client_id, state, iss, aud, claims=None, ttl=None, now=None)、compensate(client_id, state, ttl=None, now=None)、verify(client_id, token, expected_aud=None, expected_iss=None, now=None)、redeem_state(client_id, state, now)、state_status(state)、sweep_expired(now=None)、snapshot()、restore(state)、stats()。拒绝一律抛 JarmError(code, detail)。

故障与边界：①algorithms 统一转大写、去重且保留登记顺序，首选第一个，algorithms 为空或出现不认识的算法整单拒绝并报 JARM_INVALID_REQUEST，client_id、tenant、kid、secret 任一为空白也报同一码；②密钥版本从 1 开始只增，轮换写入新 kid 后旧 kid 仍保留供验签，kids 按登记先后排列，换成已存在的 kid 报 JARM_INVALID_REQUEST；③JWT 头只能是 alg、kid、typ 三个键，typ 固定 JARM，payload 必须带 iss、aud、iat、exp、state，时间用 Unix 秒，state_status 只返回 open、redeemed、expired、unknown 之一；④自定义 claims 平铺进 payload，若覆盖 iss、aud、iat、exp、state 任一保留键，整单拒绝且不得落库；⑤同一个 state 只允许签发一次，重复签发报 JARM_STATE_DUPLICATE，未登记的 client 报 JARM_UNKNOWN_CLIENT；⑥verify 逐段解 base64url，段数不对或 JSON 解不开报 JARM_RESPONSE_MALFORMED，签名对不上报 JARM_SIGNATURE_INVALID，payload 被改过但 base64 仍能解开时同样必须判签名失败，verify 返回的 claims 是 payload 的深拷贝，verify 只验签名与有效期，不核销 state，也不因为 state 已核销而拒绝；⑦verify 按 expected_aud 与 expected_iss 比对，不符分别报 JARM_AUDIENCE_MISMATCH 与 JARM_ISSUER_MISMATCH，exp 已过报 JARM_RESPONSE_EXPIRED；⑧kid 已被撤销或从未登记报 JARM_UNKNOWN_KEY；⑨客户端只登记 RS256 时收到 alg=none 或 HS256 的响应必须拒绝，不能因为签名段看着像就放行；⑩state 已核销但响应未送达时，补偿查询不能重新放行同一 state，只能返回一次性错误，补偿重签沿用原 kid 与 alg，只刷新 iat 与 exp；⑪redeem 成功返回字符串 redeemed，只接受该 client 自己的 open state，别的 client 拿同一 state 来一律按 JARM_UNKNOWN_STATE 处理，不泄漏状态是否存在；⑫sweep_expired 只扫 open 并返回扫掉的条数，已核销与已过期的保持原状；撤销当前生效 kid 报 JARM_INVALID_REQUEST，撤销未知 kid 返回 False。

硬约束：同一个 state 被多路并发核销时只能有一个成功，其余全部拿到一次性错误，stats 的 redeemed 不得翻倍，回调风暴下不能出现两条互相矛盾的终态；签名必须可复算，同一 kid、同一段签名输入算出的签名一致，签名失败或参数非法的响应不得进入 state 台账；已核销状态要随快照持久化，重启后不能把 redeemed 复原成 open；快照固定含 version、clients、states、stats 四个键，是深拷贝，restore 校验结构，缺键或类型不对报 JARM_SNAPSHOT_INVALID 且原状态不被改动；state 台账除了 ttl 还要有按客户端的硬条数上限，超出当场拒绝新签，不能悄悄淘汰旧记录。stats 至少含 clients、signed、compensated、verified、redeemed、swept。签名不需要真做非对称运算，按 kid 与 alg 从 secret 派生密钥做 HMAC-SHA256 再 base64url 编码即可，但必须能被 verify 复算。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: jarm_response_signer
- typeName: JarmResponseSigner
