# batch50-py-game-a-08

## 题面

上周的跨服竞技场里，掉线托管连着出了两类事故：一类是玩家只断了两三秒就被系统接管，回来发现自己被托管 AI 拖进了敌方阵型；另一类是玩家已经点回游戏，角色却还挂在托管手里，输入全被吞掉，客服一晚上收了四十多单。范围是 gsb/batch50-py-game-a-08 的 takeover_supervisor.py，类 TakeoverSupervisor，负责玩家掉线后的宽限计时、临时接管、受控动作执行与回归交还；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：TakeoverSupervisor(*, grace_ticks=5, frame_budget=3, max_pending=8, default_actions=("move", "dodge", "guard"))；register_character(character, *, actions=None)、mark_offline(character, now=None)、heartbeat(character, now=None)、takeover(character, now=None)、execute(character, action, now=None)、handback(character, now=None)、state_of(character)、pending_actions(character)、submit_input(character, action)、advance_frame(frames=1)、snapshot()、restore(state)、stats()。拒绝一律抛 TakeoverError(code, detail)。

故障与边界：①register_character 的 character 去空白后不得为空，重复登记报 TAKEOVER_INVALID_REQUEST，actions 去重后作为受限动作集，省略时用 default_actions；②state_of 固定返回 character、status、controller、grace_left、frozen_ticks、budget_left 六个字段，初始 status 为 online、controller 为 player、budget_left 为 frame_budget；③mark_offline 把在线角色置为 grace 并让 grace_left 等于 grace_ticks，返回与 state_of 相同的六字段结构，未登记角色报 TAKEOVER_UNKNOWN_CHARACTER；④heartbeat 只在 grace 阶段把角色拉回 online，已接管期间的心跳不改变控制权；⑤takeover 只接受宽限期已走完的 grace 角色，宽限期内报 TAKEOVER_GRACE_ACTIVE，在线角色报 TAKEOVER_NOT_OFFLINE，已接管或正在交还报 TAKEOVER_ALREADY_SUPERVISED，成功后 status 为 supervised、controller 为 supervisor、budget_left 重置为 frame_budget 并返回同一结构；⑥execute 只在接管期间可用，动作不在受限集内报 TAKEOVER_ACTION_DENIED 且不消耗预算，在线角色报 TAKEOVER_NOT_SUPERVISED，交还冻结帧报 TAKEOVER_CONTROL_FROZEN；⑦每帧动作预算为 frame_budget，预算内返回 executed 并递减 budget_left，预算耗尽后动作进入待执行队列并返回 queued，队列达到 max_pending 后报 TAKEOVER_QUEUE_FULL，execute 返回 character、action、status、frame、budget_left、pending 六项；⑧advance_frame 只接受正整数，帧号从 0 起全局递增、每次按 frames 累加，递减 grace_left 与 frozen_ticks、把被托管角色的 budget_left 重置为 frame_budget，并返回 frame、grace_expired、returned 三项，两个列表都按角色名升序；⑨handback 只接受接管中的角色，成功后 status 为 returning、controller 为 frozen、frozen_ticks 为 1 并返回同一结构，冻结这一帧里 submit_input 与 execute 都报 TAKEOVER_CONTROL_FROZEN，下一帧才回到 online 并接受玩家输入；⑩pending_actions 按入队顺序返回待执行动作，未接管或已交还时为空列表；⑪submit_input 只在 online 状态被接受，返回带 character、action、accepted 的结果；⑫交还瞬间托管队列里尚未执行的动作直接丢弃，不补发到玩家输入队列；玩家在托管期间再次掉线时接管计时从零重新累计，不沿用首次掉线时间。

硬约束：同一角色被多路 takeover 并发命中时只能有一个控制者，stats.takeovers 与成功接管次数一致，其余请求必须报 TAKEOVER_ALREADY_SUPERVISED，不能出现两个线程各自认为自己接管成功；快照固定为 version、frame、characters、stats 四个键，是深拷贝，restore 校验结构，缺键或类型不对报 TAKEOVER_SNAPSHOT_INVALID 且原状态不被改动，恢复后帧号、宽限剩余、冻结帧、预算与待执行队列都要继续可用，重启不能把托管中的角色悄悄放回玩家手里。stats 至少含 registered、offline、takeovers、handbacks、executed、queued、denied、refused 八项。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: takeover_supervisor
- typeName: TakeoverSupervisor
