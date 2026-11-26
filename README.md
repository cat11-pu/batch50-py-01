# batch50-py-safety-d-03

## 题面

权威 DNS 这周出了两起说不清的事故：一次跨机房同步，主区序列号从 4294967295 回绕成 0 之后，辅服务器坚持认为自己手上的版本更新，硬是三个月没再同步过一次；另一次给次要站点做增量，区文件里的增量段首尾接不上，进程把两段拼在一起发了出去，zone 里出现一个既没有 SOA 也没有胶水的空档，解析全线超时。还有一次运维在传送进行到一半时移除了某个 secondary 的授权，进程把整份区继续发完了，审计问起来谁也说不出那批消息本该被拦在哪里。运维主管的要求只有一句：每一次区传送都要能回答三个问题——谁授权的、发了多少、从哪个 SOA 断的；答不上来的一律按事故记。范围是 gsb/batch50-py-safety-d-03 下的 zone_transfer_governor.py，类名 ZoneTransferGovernor，负责授权、传送计划、进度记账与中断续传。

公开接口：ZoneTransferGovernor(*, max_messages=64, max_bytes=1048576, auth_ttl=300)；load_zone(zone, serial, digest, records, history=(), now)、register_key(zone, key_name)、authorize(zone, secondary, source, key_name, now)、remove_secondary(zone, secondary)、begin_transfer(zone, secondary, source, key_name, mode="auto", since=None, now=None)、record_progress(zone, secondary, messages=0, bytes_=0, last_soa=None, now=None)、complete(zone, secondary, digest, now)、abort(zone, secondary, reason="", now=None)、resume(zone, secondary, source, key_name, now)、zone_status(zone)、snapshot()、restore(state)、stats()。拒绝统一抛 TransferDenied(code, detail)。zone_status 返回 zone、serial、digest、records、watermarks、active 六个字段，records 是记录条数，watermarks 是 (secondary, serial) 升序元组；模块级 serial_is_newer(candidate, reference) 按 RFC 1982 判新旧。返回结构固定：load_zone 给 ZoneState(zone, serial, digest, records, history, loaded_at)，authorize 给 AuthGrant(zone, secondary, source, key_name, expires_at, state)，begin_transfer 与 resume 给 TransferPlan(zone, secondary, mode, since, serial, messages, digest)，record_progress 给 ProgressReport(zone, secondary, mode, messages, bytes_sent, remaining_messages, remaining_bytes, last_soa)，complete 给 TransferReceipt(zone, secondary, mode, serial, digest, messages, bytes_sent, state)。

故障与边界：①serial 必须是 0 到 2 的 32 次方减一之间的整数，records 为空或标识为空报 INVALID_REQUEST；②未登记 TSIG 密钥名或未授权时报 NOT_AUTHORIZED，source 与 key_name 任一不符报 AUTH_MISMATCH；③授权按 auth_ttl 过期，过期后必须重新授权才能开始传送；④auto 模式下 since 等于当前 serial 时只回单 SOA，messages 为 1；⑤since 落后时走增量，messages 等于差值的两倍再加二，显式 axfr 的 messages 等于记录数加二；⑥since 比当前 serial 新报 SERIAL_REGRESSION；⑦同一 (zone, secondary) 只允许一个在途传送，再次开始报 TRANSFER_IN_PROGRESS，不同 secondary 的进度互不影响；⑧进度按 messages 与 bytes_ 累计，超过 max_messages 或 max_bytes 报 BUDGET_EXCEEDED，传送立即终止并保留最后确认的 SOA；⑨complete 的 digest 必须等于区摘要，不符报 DIGEST_MISMATCH 且传送保持可重试，成功后只更新该 secondary 的水位；⑩abort 记录最后确认的 SOA 与已发字节，resume 从该 SOA 续传；⑪serial 恰好为 2 的 32 次方减一之后回绕到 0 时，比较必须按模运算判新，不能按整数大小；⑫secondary 在 AXFR 进行中被移除授权时，当前传送可以完成，但后续消息必须拒绝续传，增量区间与 journal 首尾不衔接时必须回落 AXFR，不能拼接出空洞。

硬约束：同一 zone 的传送开始、进度、完成、中止在 zone 级锁内串行，按 secondary 隔离计数，水位与台账不得互相污染；快照深拷贝，含 version、zones、keys、auths、active、aborted、watermarks、counters 八个键，恢复后在途传送与水位必须一致，非法结构抛 SNAPSHOT_INVALID 且不改动现有状态。值班同学还提到，同一台 secondary 反复重连时水位被来回刷写，恢复后必须先以水位为准，再决定走增量还是整份重发。stats 固定返回 zones_loaded、authorizations、transfers_started、transfers_completed、transfers_aborted、budget_aborted、messages_sent、bytes_sent、denied 九个键。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-d-03
- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: zone_transfer_governor
- typeName: ZoneTransferGovernor
- topic: 权威 DNS 区传送治理：AXFR/IXFR 授权、序列号回绕比较与传送预算
