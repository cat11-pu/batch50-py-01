# batch50-py-safety-a-08

## 题面

客服中心的代客操作最近连吃两张审计单：有客服拿自己提交的申请单给自己放行，从发起、审批到开工一气呵成，事后查不到第二个人签过字；同一客服同时对同一个客户开了两个代客会话，一边查订单一边改资料，出了问题对不上哪个动作属于哪次授权；申请范围里明明写的只是只读，实际却能发起退款；还有会话到期之后动作票据还能再用十几分钟，客户本人点了终止也没能立刻生效。范围是 gsb/batch50-py-safety-a-08 的 impersonation_session_broker.py，类 ImpersonationBroker，负责代客申请、双人审批、受限会话、动作票据与撤销。

公开接口：ImpersonationBroker(*, session_ttl=900, ticket_ttl=120)；grant_approver(principal)、revoke_approver(principal)、request(cs_id, target_id, reason, actions)、approve(request_id, approver)、start(request_id)、act(session_id, action)、issue_ticket(session_id, action)、redeem_ticket(ticket_id)、revoke(session_id, actor, reason)、expire()、session_view(session_id)、snapshot()、restore(state)、stats()，时间参数统一 now 取整秒。拒绝一律抛 ImpersonationError(code, detail)。request 与 approve 返回 dict，键含 request_id、cs_id、target_id、actions、state、approved_by、session_id；start 与 session_view 返回 dict，键含 session_id、request_id、target_id、actions、state、expires_at；issue_ticket 返回 dict，键含 ticket_id、session_id、action、expires_at、state；act 返回 dict，键含 session_id、action、allowed、count；redeem_ticket 返回 dict，键含 ticket_id、session_id、action、redeemed_at；revoke 返回 dict，键含 session_id、state、revoked_by、revoked_at；grant_approver 返回 principal 与 approver 两个键，revoke_approver 首次返回真、再次撤销返回假。

故障与边界：①客服号、目标用户号、理由、动作列表任一为空或动作含非字符串项抛 IMP_INVALID，客服与目标是同一人抛 IMP_SELF，动作去重后按字典序保存；②申请号从 req-1 递增，新申请 state 为 pending，approved_by 与 session_id 为空；③同一客服对同一目标已有待批、已批或活动会话时，再发起抛 IMP_LIMIT；④审批人必须是登记在册的审批人，否则抛 IMP_NOT_APPROVER，发起人自批抛 IMP_SELF，非 pending 的申请再批抛 IMP_REQUEST_STATE；⑤start 只对 approved 生效，否则抛 IMP_REQUEST_STATE，会话号从 imp-1 递增，state 为 active，expires_at 为启动时刻加 session_ttl；⑥act 只放行申请范围里的动作，越权动作抛 IMP_SCOPE 并计入 denied_actions，不写入动作计数；⑦会话到期时刻含等于即失效，act 与 issue_ticket 抛 IMP_SESSION_EXPIRED，expire() 把到期会话置为 expired 并返回条数；⑧revoke 把会话置为 revoked 并记录撤销人与时间，重复撤销幂等且不重复计 revocations，撤销后 act 抛 IMP_SESSION_REVOKED；⑨票据号从 tkt-1 递增，expires_at 为签发时刻加 ticket_ttl，state 从 unused 起、兑换后为 spent，只能兑换一次，第二次抛 IMP_TICKET_SPENT，到期时刻含等于抛 IMP_TICKET_EXPIRED；⑩未知申请号抛 IMP_REQUEST_UNKNOWN，未知会话号抛 IMP_SESSION_UNKNOWN，未知票据号抛 IMP_TICKET_UNKNOWN；⑪另外三条必须处理：目标在会话中撤销后，已签发但未使用的动作票据必须立即失效；代客会话内不得改密、改因子或再发起代客，即使申请范围里包含了账号管理类动作；审批人权限在放行后被收回时，已启动会话要在下一次动作前重新校验；⑫撤销与动作并发时以撤销为准，撤销一旦生效就不再允许任何动作成功。

硬约束：request、approve、start、act、issue_ticket、redeem_ticket 与快照全程持锁，同一张动作票据被多路并发兑换时只能成功一次，其余按已消费失败，actions 与 denied_actions 计数不得错账；快照覆盖 requests、sessions、tickets、approvers、counters，恢复后未过期会话按剩余时间继续有效、票据的一次性状态与审批人登记都在，结构非法抛 IMP_SNAPSHOT 且原状态不变。stats 固定返回 requests、approvals、sessions、actions、denied_actions、tickets、redeemed、revocations、expired。

验收：`python3 -m pytest -q tests` 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发兑换与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: impersonation_session_broker
- typeName: ImpersonationBroker
- file: impersonation_session_broker.py
