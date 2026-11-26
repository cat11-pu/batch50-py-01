# batch50-py-safety-c-07-p2

## 题面

图形工作站这批席位设备又出事了：白班和夜班交接时两个会话同时抓着一块显示节点不放，画面互相撕裂；有台机器休眠唤醒后旧会话已经不在了，设备仍显示被占用，新登录的人怎么都挂不上；还有一次切换活跃会话，旧会话的授予先撤了、新会话的授予又失败，结果两边都用不了设备。值班手册里写的是“一块屏同时只能归一个会话”，可实际跑起来完全不是这样，交接班和休眠唤醒这两种场景每次都要人工去改设备归属。范围是 gsb/batch50-py-safety-c-07-p2 下的 seat_access_broker.py，类 SeatAccessBroker，维护席位会话与显示设备节点的归属，负责授予、撤销、活跃会话切换和崩溃残留清扫。

公开接口：register_session(name, *, seat, active=False)；register_device(path, *, state="ready")；set_device_state、set_session_alive、set_session_active；attach_session(session, device, *, now) 返回是否新增授予；detach_session(session, *, now, device=None) 返回撤销数；switch_active(seat, session, *, now) 返回 revoked、granted、session；holders(device=None)；session_view、device_view；sweep(*, now) 返回 SweepReport（removed、kept）；audit_log() 返回 AuditEntry（op、session、device、at）元组；snapshot、restore、stats。拒绝时抛 SeatError(code, detail)。

故障与边界：①会话名与席位非空，重名报 SEAT_DUPLICATE_SESSION；设备路径先按 POSIX 规范化，必须落在 /dev/dri/ 下，规范化后重名报 SEAT_DUPLICATE_DEVICE，越界或相对路径报 SEAT_INVALID_REQUEST；②只有活跃会话能获得设备，非活跃报 SEAT_SESSION_INACTIVE；未登记会话与设备分别报 SEAT_UNKNOWN_SESSION、SEAT_UNKNOWN_DEVICE；③同一设备任何时刻最多一个持有者，被占用时报 SEAT_DEVICE_BUSY 且原持有者不变；状态为 faulted 的设备拒绝授予并报 SEAT_DEVICE_FAULTED；④attach 成功返回 True 并写一条 grant 审计，同一会话重复 attach 同一设备必须幂等，返回 False 且 grants 计数不得重复累加；⑤detach 指定设备只撤该设备，不给设备则撤该会话全部授予，返回撤销条数，没有可撤的返回 0 而不报错，每条撤销写 revoke 审计；⑥switch_active 必须先撤销旧活跃会话的全部授予再给新会话授予，审计顺序必须全部 revoke 在前、grant 在后，旧会话置为非活跃；⑦切换过程中给新会话授予失败时，旧会话原有的访问必须保持，不能出现新旧两边都没有设备的情况；⑧目标会话已经是该席位唯一活跃会话时按空操作处理，返回全零且不写审计；⑨未知席位报 SEAT_UNKNOWN_SEAT，拿别的席位的会话来切换报 SEAT_WRONG_SEAT；⑩sweep 按会话存活性清除崩溃残留的授予，removed 按设备路径升序，kept 是保留条数，只计入 swept 不计入 revokes；⑪快照含 version、devices、sessions、grants、counters、audit，grants 与 holders() 同构，快照与内部状态不共享，restore 结构非法报 SEAT_SNAPSHOT_INVALID 且不改动现有数据；⑫被拒绝的操作计入 refused。

硬约束：同一设备并发 attach 只允许一个会话成功，其余必须拿到 SEAT_DEVICE_BUSY，持有者与审计都只能有一条；快照恢复后设备状态、会话存活标记、授予关系与计数器必须一致，恢复出来的结构与快照互不共享。只做本地实现，不得改测试、跳过或按固定输入写死；并发与重启自行验证。验收运行 python3 -m pytest -q tests，15 条全部通过。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: seat_access_broker
- typeName: SeatAccessBroker
