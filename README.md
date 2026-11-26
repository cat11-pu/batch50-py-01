# batch50-py-game-a-02

## 题面

世界事件这周被投诉得厉害：周三凌晨停服四十分钟，回来以后两个整点活动一个都没开，玩家白等；另一个活动取消之后，已经领过奖励的号还能再点一次领取，客服不知道该不该回收；跨零点那场夜市在 UTC 与服务器时区之间错了一天，运营按日历对账时发现窗口落到了前一天。范围是 gsb/batch50-py-game-a-02 的 world_event_window_planner.py，类 WorldEventWindowPlanner，把周历事件展开成带开始、结束时间戳的窗口，并在服务停机后按补偿上限补齐错过的窗口。

公开接口：WorldEventWindowPlanner(*, start_ts=0, compensation_cap=3, utc_offset_minutes=0)；schedule(event_id, *, weekday, start_minute, duration_minutes=30, now=None)；cancel_event(event_id, now=None)；advance(to_ts)；windows_between(start_ts, end_ts)；claim_window(window_id, account, now=None)；compensated_count()；event_record、window_of、open_windows；snapshot、restore、stats。所有拒绝统一抛 WorldEventError(code, detail)。schedule 返回事件记录，含 event_id、weekday、start_minute、duration_minutes、cancelled 与首次开始时间戳 first_start_ts；窗口记录含 window_id、event_id、start_ts、end_ts、status、compensated 与 claims；claim_window 返回 points、account、window_id 与 compensated。

故障与边界：①weekday 取 0-6（周一为 0），start_minute 取 0-1439，duration_minutes 必须为正，非法报 WORLD_EVENT_INVALID_REQUEST，空 event_id 同样拒绝；②同一 event_id 重复登记报 WORLD_EVENT_DUPLICATE_EVENT，已取消的事件也不能复用编号；③事件按服务器本地时区（UTC 加 utc_offset_minutes）落在指定星期与分钟，周与周之间按七天展开，窗口可以跨本地零点，服务端不得依赖运行机器的系统时区；④advance 只允许时间前进，回拨报 WORLD_EVENT_CLOCK_REWIND，回拨后时钟与窗口都不能被改动；⑤同一时间戳重复推进不得生成重复窗口，跨过开始时刻生成状态为 open 的窗口，跨过结束时刻窗口转 closed，窗口编号在同一事件内唯一；⑥windows_between 按开始时间升序返回左闭右开区间，起止颠倒报 WORLD_EVENT_INVALID_RANGE；⑦每个窗口只能被领取一次，重复领取报 WORLD_EVENT_DUPLICATE_CLAIM，已被领走或已结束再领报 WORLD_EVENT_WINDOW_CLOSED，正常窗口领取 100 分；⑧取消事件后不再生成新窗口，再次取消报 WORLD_EVENT_EVENT_CANCELLED，已有窗口的领取状态保留；⑨停机时长超过补偿上限时只补最近若干窗口，且补出的窗口标记为补偿态而非正常态，补偿态领取按半额计；⑩事件被取消后已发放的窗口奖励不回收，但窗口不能再被领取；⑪未知事件或窗口报 WORLD_EVENT_UNKNOWN_EVENT / WORLD_EVENT_UNKNOWN_WINDOW；⑫snapshot 深拷贝时钟、事件、窗口与计数，restore 结构非法报 WORLD_EVENT_SNAPSHOT_INVALID 且原状态不变。stats 至少含 events、cancelled、windows、opened、compensated、dropped、claims、duplicates、closed、clock_rewinds。

硬约束：多个线程用同一目标时间戳推进时只能生成一次窗口，时钟检查与窗口生成必须在同一把锁内完成，重复推进整体返回空结果；快照恢复后服务器时钟、事件取消标记、窗口领取状态和补偿计数都要还原，且不得与调用方共享可变结构；补偿与跨周展开单次最多处理 compensation_cap 个错过窗口，不得因停机一周就把全部历史窗口一次性铺开。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: world_event_window_planner
- typeName: WorldEventWindowPlanner
