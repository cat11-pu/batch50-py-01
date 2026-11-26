# batch50-py-safety-a-01

## 题面

上周统一登录切流后，两个接入方在无痕窗口里反复被弹到登录页，另有一批用户点完授权跳回来停在白屏，客服按重复登录归了三十多单。排查下来不是会话本身丢了，而是静默认证这一段的登记与判定各写各的：同一个 state 能被回调两次，会话探测的结果也没有统一的归类口径。范围是 gsb/batch50-py-safety-a-01 的 oidc_silent_auth_broker.py，类 SilentAuthBroker，负责一次 prompt=none 静默认证从发起到回跳的登记、会话探测与结果归类；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：SilentAuthBroker(*, max_pending_per_client=8, max_pending_per_tenant=32, pending_ttl=300)；register_client(client_id, tenant, redirect_uris, now)、client_record(client_id)、register_session(session_id, user, tenant, auth_time, now)、end_session(session_id, now)、begin(client_id, redirect_uri, login_hint=None, max_age=None, session_id=None, now=None)、complete(state, now=None)、cancel(state, now=None)、pending_for_session(session_id)、state_status(state)、expire(now=None)、snapshot()、restore(state)、stats()。拒绝一律抛 SilentAuthError(code, detail)。

故障与边界：①client 的 redirect_uris 去空白、去重后按字典序保存，重复登记同一 client 报 SILENT_AUTH_INVALID_REQUEST，避免同一接入方出现两套回调白名单，client_id、tenant 为空或 redirect_uris 为空也按同一错误码拒绝；②begin 的 redirect_uri 必须与登记值逐字一致，多一个斜杠也算不一致，报 SILENT_AUTH_REDIRECT_MISMATCH，未登记 client 报 SILENT_AUTH_UNKNOWN_CLIENT；③state 至少 16 个字符且不可预测，expires_at 等于 created_at 加 pending_ttl，status 从 pending 起步，state_status 只返回 pending、completed、cancelled、expired、unknown 之一；④会话存在且未结束时 complete 给 success，subject 与 session_id 都取自会话，reason 为 session_reused；⑤会话缺失或已结束时归 login_required、reason 为 no_session，subject 与 session_id 留空，让前端干净地回到登录页；⑥会话租户与 client 租户不一致归 interaction_required、reason 为 tenant_mismatch，subject 与 session_id 同样留空，不得当成成功，跨租户复用会话是这次工单里最危险的一种；⑦login_hint 与当前会话用户不一致时必须归 login_required，不能直接复用会话把别人的登录态带过去；⑧max_age 已经超时的会话只能走交互，不能按剩余 cookie 有效期放行；⑨回跳丢失后重放同一 state 只能拿到一次性错误，不得重新触发会话探测，也不得再发一次断言；⑩cancel 只对 pending 生效，重复取消返回 False，已取消再 complete 报 SILENT_AUTH_STATE_CANCELLED；⑪expire 扫掉到期请求并计数，complete 撞上已过期 state 报 SILENT_AUTH_STATE_EXPIRED，未登记 state 报 SILENT_AUTH_UNKNOWN_STATE；⑫每个 client 与每个租户的未决条数各有硬上限，超出报 SILENT_AUTH_CAPACITY_EXCEEDED，进入终态后额度立即恢复，不能靠定时清理才释放。

硬约束：同一个 state 被多路回跳并发 complete 时只能产生一条成功记录，completed 计数不得翻倍，也不许写出两条互相矛盾的终态，回调风暴下不能出现一半成功一半报未知；快照固定为 version、clients、sessions、requests、stats 五个键，是深拷贝，restore 校验结构，缺键或类型不对报 SILENT_AUTH_SNAPSHOT_INVALID 且原状态不被改动，恢复后未决请求、过期时刻与各项计数都要继续可用，重启不能把未决请求清空，恢复时以快照里的终态为准，不能把已完成的 state 重新算成未决；时间统一用 ISO8601 UTC 字符串，now 省略时取当前 UTC，过期判定按解析后的时刻比较，不做字符串比较。stats 至少含 clients、sessions、begun、completed、login_required、interaction_required、cancelled、expired、replayed，其中 completed 统计被 complete 消费掉的请求数，含 login_required 与 interaction_required 两种结果。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；题面点到的每一项都要落到代码行为上；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: oidc_silent_auth_broker
- typeName: SilentAuthBroker
