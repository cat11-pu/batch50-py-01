# batch50-py-game-a-12

## 题面

客服侧这周收到成堆昵称工单：两个账号同时抢一个昵称，两边都提示成功，实际只有一个能用，另一个玩家的改名卡已经扣掉了；改名时新名字一会儿提示被占、一会儿又能用，旧名字却直接回到公共池被路人秒抢；被释放的昵称本该留一段保留期给原主反悔，结果立刻能被别人注册；同一个改名请求被网关重试后扣了两次冷却，玩家第三次改名要等一个月；客服想追溯某个昵称曾经属于谁，系统只回“无记录”，只能人工翻工单。改动落在 gsb/batch50-py-game-a-12 的 name_reservation.py，类名 NameReservation，昵称占位、释放、改名、保留期回收与历史记录都由它负责。运营要求昵称台账既能扛住并发抢注，也要在服务重启后原样恢复，不能靠重启把冷却和保留期洗掉。

公开接口：NameReservation(*, retention=604800, rename_cooldown=2592000, max_history=200)；reserve(name, account, *, now, request_id=None)、release(name, account, *, now)、rename(account, new_name, *, now, request_id=None)、lookup(name)、owner_of(name)、expire_sweep(*, now)、history_of(name)、rename_ready_at(account)、snapshot()、restore(state)、stats()。所有拒绝统一抛 ReservationError(code, detail)。

返回值约定：名字视图包含 name、status、owner、held_until、last_owner；改名结果包含 account、old_name、new_name、renamed、replayed、cooldown_until；历史记录包含 name、account、action、at。

故障与边界：①昵称须匹配 ^[a-z][a-z0-9_]{2,15}$，改名目标同样按此校验，账号不能为空白，否则抛 NAME_INVALID；②注册是原子占位，必须一步完成，不能先查后写留下空隙，同一昵称已有主人时抛 NAME_TAKEN；③当前主人重复提交同名注册按幂等处理，不重复计数、不追加历史；④释放后进入保留期，owner_of 返回空，lookup 返回 retention，保留期内的昵称不出现在公共池列表里，除原账号外的任何注册都抛 NAME_RETENTION_HELD；⑤保留期内原账号可以直接取回，取回后保留期立即结束；⑥expire_sweep 在保留期截止时刻及之后把昵称放回公共池并返回回收数量，重复扫描返回零，未到期的昵称保持原状；⑦改名先占新名再释放旧名，旧名进入保留期，成功后写入冷却截止时间，前后两个名字的变更写在同一条历史链上；⑧冷却未过再次改名抛 NAME_COOLDOWN，且不延长冷却；⑨带 request_id 的请求重放返回首次结果且只计一次，同 request_id 换目标抛 NAME_REQUEST_CONFLICT；⑩历史按时间追加，每条记录包含名字、账号、动作与时间，动作取 reserve、release、rename 三种，客服可查完整归属轨迹；⑪保留期到期后昵称回到公共池，但历史归属记录必须永久保留，供客服追溯；⑫改名失败时已占位的新名字要立刻释放，且不计入改名冷却；stats 固定返回 reserved、released、renamed、expired、active、retention 六项。

硬约束：同一昵称的并发注册只能有一个成功，其余必须拿到 NAME_TAKEN，reserved 计数只加一，改名失败不得留下半占位状态；快照恢复后名字状态、保留期截止、改名冷却、请求记录与全部统计必须和恢复前一致，且不与快照共享可变结构。

验收：`python3 -m pytest -q tests` 15 条全过；不得修改测试、跳过用例或针对固定输入写死；并发与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: name_reservation
- typeName: NameReservation
