# batch50-py-safety-d-23

## 题面

桌面团队这周收到三类投诉。第一类来自客服坐席：同一个账号既在用户级规则里被拒绝发送某个方法调用，又在所属组的规则里被允许，机器重启后行为不一致，有时消息直接发出去，有时被拦下来，值班只能靠试。第二类来自运维：一个 well-known 名称的所有者进程崩溃后，总线把名称转给了排队的第一位，那位本来没有发消息的权限，转过去之后立刻开始广播方法调用，拦都拦不住。第三类来自审计：策略文件刚重载完，一条已经发出、还没返回的方法调用被改判成拒绝，客户端收到错误，可同一条消息在旧策略下本来是允许的，审计要求给出这条消息到底按哪版策略裁决。范围是 gsb/batch50-py-safety-d-23 的 dbus_policy_broker.py，类名 DbusPolicyBroker，负责连接登记、收发两侧的策略裁决、名称所有权与待决调用管理。

公开接口：DbusPolicyBroker(*, max_connections=64, max_names=256, call_timeout=30)；add_connection(conn_id, *, uid, pid, groups=(), now) -> Connection；remove_connection(conn_id, *, now) -> dict；load_policy(rules, *, now) -> int；evaluate_send(conn_id, *, target, message_type="method_call", eavesdrop=False, now) -> Verdict；evaluate_receive(conn_id, *, sender, message_type="method_call", eavesdrop=False, now) -> Verdict；request_name(conn_id, name, *, now) -> str；release_name(conn_id, name, *, now) -> int；names()；record_call(conn_id, *, seq, target, method, now) -> PendingCall；expire_calls(*, now)；stats()；snapshot()；restore(state)。拒绝时抛 DbusPolicyError(code, detail)。规则用 PolicyRule(source, subject, subject_kind, target, message_type, verdict) 传，source 只认 system 与 site，subject_kind 只认 user 与 group，message_type 取 method_call、signal、any，verdict 取 allow 与 deny。

故障与边界：①连接标识重复抛 DBUS_DUPLICATE_CONNECTION，连接数超过 max_connections 抛 DBUS_CAPACITY_EXCEEDED，未登记连接参与任何操作抛 DBUS_UNKNOWN_CONNECTION。②唯一名按登记顺序分配为 :1.1、:1.2，连接断开后号不回收。③deny 优先于 allow：一条消息只要命中任何 deny 就拒绝，命中 allow 才放行，都不命中按默认放行，reason 分别为 rule_deny、rule_allow、default_allow。④同一连接既有用户级 deny 又有组级 allow 时，按 deny 优先，不按组优先。⑤eavesdrop 默认拒绝，reason 为 eavesdrop_denied，只有显式 allow 规则才能放行。⑥同一条消息的发送侧与接收侧分别裁决，接收侧按接收连接的凭据匹配规则，两侧结论要能单独查询。⑦名称请求空闲时直接成为所有者并返回 owner，同一连接重复请求幂等返回 owner，被他人占用时排队并返回 queued:<位次>；名称数量超过 max_names 抛 DBUS_CAPACITY_EXCEEDED，release_name 只有调用者是所有者时才返回 1，否则返回 0。⑧名称所有者断开后，队列中下一位要重新过一遍策略裁决，通过才转交，不通过则跳过并记录原因。⑨待决调用按连接与序列号去重，重复登记返回原记录并把 deduplicated 加一；超过 call_timeout 的调用由 expire_calls 清理，返回带 seq 与 reason 为 timeout 的条目，槽位同时释放。⑩策略重载整体换表并把版本号加一，只影响重载之后登记的新消息；重载时已在途的方法调用按发起时记录的版本裁决，不得中途改判。⑪names 按名称升序返回，每条带 owner 与 queue；未登记连接的请求一律拒绝。⑫快照保存策略版本、连接表、名称归属与待决调用，非法快照抛 DBUS_SNAPSHOT_INVALID 且不改现状；stats 给出 connections、names、rules_version、pending、expired、deduplicated、denied 七项。

硬约束：名称状态迁移按名称串行，连接表、规则表与名称表都有硬上限，超限当场拒绝而不是覆盖旧条目；快照与活动状态完全脱钩，恢复后连接、名称队列、待决调用与版本原样回来，重启不得把已超时清理的调用借快照带回。验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: dbus_policy_broker
- typeName: DbusPolicyBroker
