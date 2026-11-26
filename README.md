# batch50-py-safety-d-01

## 题面

计费网关这周连着上了三张事故单：跨机房演练里，对端回过来的 CEA 少了信用控制应用，网关照样把 CCR 发过去，整批话单半小时后被判成无主请求；另一处是链路抖动，客户端重传同一个 CCR，账上却按两笔预留扣了额度，事后对账差了近四千条；还有一台前置机被摘掉之后，老连接上迟到的 CCA 仍然被结算，同一会话被扣了两次。整改会上运营把口径说得很死：每一笔预留都要能从票据追到会话、从会话追到 peer，谁在什么时候放行、谁在什么时候归还，必须逐条对得上账；演练里还暴露了网关重启后去重记录整片清空，重放的请求被当成新请求又扣了一遍。对等会话的生命周期、额度预留和应答去重因此都要有据可查，断链、重启、并发都不能出现重复扣额。范围是 gsb/batch50-py-safety-d-01 下的 diameter_peer_guard.py，类名 DiameterPeerGuard，负责 peer 连接状态、能力交换、信用控制会话与配额预留。值班同学还补了一条：已经关掉的 peer 仍留在路由结果里，新会话被分到一条正在关闭的连接上，请求发出去就没了下文。

公开接口：DiameterPeerGuard(*, max_peers=8, max_applications=6, max_sessions=32, dedup_window=128, max_retransmit=3)；open_peer(peer, origin_host, now)、exchange_capabilities(peer, offered, wanted, now)、peer_state(peer)、routes(application)、send_ccr(session_id, subscriber, peer, requested, hop_by_hop=None, end_to_end=None, now=None)、handle_answer(session_id, hop_by_hop, result, granted=0, now=None)、reclaim(session_id, now=None)、close_peer(peer, now)、session_status(session_id)、snapshot()、restore(state)、stats()。所有拒绝统一抛 DiameterError(code, detail)。返回结构固定：open_peer 给 PeerRecord(peer, origin_host, state, applications, opened_at)；exchange_capabilities 给 CapabilityReport(peer, state, granted, rejected)；send_ccr 给 CcrTicket(session_id, hop_by_hop, end_to_end, peer, requested, reserved, state)；handle_answer 与 reclaim 给 Settlement(session_id, peer, state, requested, used, returned)；session_status 给 state、reserved、used 三个字段。

故障与边界：①open_peer 只把 peer 推进到 WaitConnAck，重复打开报 PEER_DUPLICATE；②能力交换要求 wanted 是 offered 的子集，通过后按字典序给出 granted 并转 Open，路由表只按 granted 里的应用登记，不匹配报 CAPABILITY_MISMATCH 且 peer 回到 Closed；③非 WaitConnAck 状态再交换报 PEER_STATE_INVALID，未知 peer 报 PEER_UNKNOWN；④send_ccr 只能发给 Open 且支持该应用的 peer，否则报 PEER_NOT_OPEN；⑤首次请求生成 h-1、e-1 递增标识，reserved 等于 requested，会话进入 pending；⑥同一 (session_id, hop_by_hop) 再次发送回缓存票据并标记 retransmitted，不得二次预留；⑦重传次数超过 max_retransmit 报 TRANSMIT_EXHAUSTED，会话关闭并释放预留；⑧handle_answer 成功按授予量结算并归还余量，失败整笔释放，未知标识报 ANSWER_STALE 且不动余额；⑨reclaim 关闭会话、归还未用预留，再次 reclaim 返回 0；⑩requested 非正整数或会话标识为空报 REQUEST_INVALID，peer 与 session 各自封顶，超出报 PEER_CAPACITY_EXCEEDED / SESSION_CAPACITY_EXCEEDED；⑪CCA 授予额度小于请求量时必须按授予量重算可用余额，不能沿用请求量继续放行；⑫同一会话的更新与终止并发到达时，终止先结算再关闭，迟到的更新必须回失败而不是重新打开；备份 peer 重路由后原 peer 的迟到应答按会话与 Hop-by-Hop 丢弃，不得二次结算。

硬约束：会话状态迁移按 session_id 串行，同一时刻只有一个迁移生效，计数与预留不得丢；快照深拷贝，恢复后 peer 状态、预留额度与去重窗口必须与快照一致，非法结构抛 SNAPSHOT_INVALID 且不改动现有数据。stats 固定返回 peers_opened、capability_rounds、capability_rejected、ccr_sent、retransmit、transmit_exhausted、answers_settled、units_reserved、units_returned、reclaimed 十个键。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-d-01
- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: diameter_peer_guard
- typeName: DiameterPeerGuard
- topic: Diameter 对等会话与信用控制：能力交换、Hop-by-Hop 去重与配额预留
