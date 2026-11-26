# batch50-py-safety-d-06

## 题面

监控平台这周连开三张单子：一台核心交换机重启之后，两个采集器互相把对方的请求判成过期，网管日志里成片 notInTimeWindow；另一台设备时钟被 NTP 纠正过一次，几分钟内同一条请求又被接受了一遍，去重等于没有；还有一台设备的 boots 打满以后，监控侧收到的应答里 boots 变回 0，去年的老报文重新算有效。范围是 gsb/batch50-py-safety-d-06 的 snmp_usm_guard.py，类 SnmpUsmGuard，负责 SNMPv3 USM 权威引擎侧的发现应答、密钥本地化与请求校验；这些入口目前调用即抛 NotImplementedError，采集链路等于没有认证。

公开接口：SnmpUsmGuard(*, time_window=150, max_window_entries=64, per_user_limit=20, rate_period=60.0, grace_seconds=30.0, clock=None)；register_engine(engine_id, boots=0, now=None)、register_user(engine_id, user, secret)、discover(engine_id=None)、localize_key(engine_id, user, secret=None)、verify_request(msg_id, engine_id, user, boots, engine_time, digest)、rotate_key(engine_id, user, secret)、expire_keys(now=None)、restart(engine_id=None)、purge_window(engine_id=None)、status(engine_id=None)、snapshot()、restore(state)、stats()。拒绝一律抛 UsmError(code, detail)。engine_time 一律由注入的 clock 相对引擎启动时刻推进，不读系统壁钟。

故障与边界：①不带 engineID 的 discover 返回 kind=discovery_report、engine_id、boots、engine_time，重复发现不消耗任何用户的速率额度；②engineID 未登记报 USM_UNKNOWN_ENGINE，本地化碰到未登记用户报 USM_UNKNOWN_USER；③本地化摘要固定 64 位小写十六进制，由 engineID 与用户密钥共同派生，进程内不保存密钥明文，同一组输入重复调用 digest 与 generation 不变；同一用户名在两台引擎上各自本地化，缓存必须按 engineID 分开，不能只按用户名共用一条；④请求携带的 boots 与当前不一致，或 engine_time 与本地时刻的偏差超过 time_window，一律判 notInTimeWindow，accepted 为 False；⑤同一 msgID 与 boots/time 组合在窗口内只接受一次，第二次 reason 为 replay 且 stats 的 replays 加一；⑥摘要不符与用户不存在都抛 USM_AUTH_FAILURE_REPORT，detail 是同一个 UsmReport 结构，reason 与字段完全一致，不能靠错误形态差异枚举出哪些用户名存在；⑦rotate_key 产生新 generation，send 与 recv 都为 True，同一时刻重复轮换报 USM_KEY_ROTATION_CONFLICT，clock 走动之后才允许再换；⑧轮换后旧密钥在 grace_seconds 内仍可验签，decision.generation 仍是旧代次，超出宽限期由 expire_keys 清理并返回清理条数；⑨每用户每 rate_period 内请求数超过 per_user_limit 报 USM_RATE_LIMITED；⑩重放窗口条目按 max_window_entries 封顶，满了淘汰最旧的而不是拒绝新请求，purge_window 返回清理条数；⑪restart 让 boots 加一、engine_time 归零，重启前发出的报文不能因为时间看起来还在窗口里就继续有效；⑫boots 顶到 2147483647 之后钳制在原值，绝不能回绕成 0，否则旧报文会重新变成有效。

硬约束：verify_request 与 rotate_key 并发时用同一把可重入锁保护引擎上下文、密钥代次与重放窗口，同一条 msgID 被多路并发校验只能产生一条 accepted，计数不得翻倍，也不能出现一半成功一半报错；快照固定 version、engines、keys、window、counters、stats 六个键，是深拷贝，restore 逐项校验结构，缺键、版本不符或类型不对报 USM_SNAPSHOT_INVALID 且原状态不被改动，恢复后 boots、engine_time 水位与已消费的 msgID 继续生效，重启不能把重放窗口清空。status 返回 engine_id、boots、engine_time、users（用户数）、keys（密钥条数）、window_entries（窗口条目数）；stats 至少含 discovered、localized、accepted、not_in_time_window、replays、auth_failures、rotated、expired_keys、rate_limited。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: snmp_usm_guard
- typeName: SnmpUsmGuard
