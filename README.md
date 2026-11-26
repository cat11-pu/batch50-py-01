# batch50-py-safety-a-07

## 题面

值班室换班之后，共享终端上的老问题集中爆了出来：同一张工牌在隔壁终端又刷了一次，两台屏幕都显示已登录，后一个人能直接看到前一个人的单子；有人刷卡时读卡器抖了两下，同一条刷卡事件被上报两遍，系统给他开了两个会话，下班退出只关掉其中一个；换班的人点了挂起就走，回来发现会话已经过期，凭据再也取不回来；还有终端断网一阵后恢复，挂起的会话照样被放出来，没人确认过还是不是本人在用。范围是 gsb/batch50-py-safety-a-07 的 badge_session_switcher.py，类 BadgeSessionSwitcher，负责刷卡建会话、挂起与恢复、单终端并发上限和离线宽限。

公开接口：BadgeSessionSwitcher(*, max_active_per_terminal=2, max_terminals_per_badge=3, idle_timeout=300, suspended_ttl=900, offline_grace=120)；tap(terminal_id, badge_serial, seq)、suspend(terminal_id)、resume(terminal_id, badge_serial)、logout(terminal_id, badge_serial=None)、list_active(terminal_id=None)、mark_offline(terminal_id)、mark_online(terminal_id)、sweep()、session_view(session_id)、snapshot()、restore(state)、stats()，时间参数统一 now 取整秒。拒绝一律抛 BadgeError(code, detail)。tap 返回 TapResult，字段有 session_id、terminal_id、badge_serial、state、status、replayed；list_active 与 session_view 返回 SessionRecord，字段有 session_id、terminal_id、badge_serial、state、opened_at、last_seen_at、expires_at；suspend 返回 dict，键为 terminal_id、suspended、count；mark_offline 返回 terminal_id、offline_since，mark_online 返回 terminal_id、online；sweep 返回 dict，键为 suspended、purged。

故障与边界：①空终端号、空工牌号、非正 seq 抛 BADGE_INVALID，未知会话号抛 BADGE_SESSION_UNKNOWN；②同一 (terminal, badge, seq) 重复上报必须幂等，返回首次结果并把 replayed 置真，不新增会话也不重复计 opened；③比该终端该工牌已受理最大 seq 更小的旧事件抛 BADGE_STALE，不得改动任何会话；④同一工牌在同一终端已活动时，更大的 seq 返回 existing 并复用原 session_id；⑤会话号从 sess-1 递增，新建后 state 为 active、expires_at 为空；⑥suspend 把该终端所有活动会话置为 suspended，expires_at 为挂起时刻加 suspended_ttl，返回被挂起的会话号列表与条数；⑦resume 只认该终端该工牌的挂起会话，复活同一个 session_id 并清空 expires_at，找不到、已到期或该工牌已在别处活动时抛 BADGE_RESUME；⑧sweep 把空闲达到 idle_timeout（含等于）的活动会话置为 suspended，并把到期的挂起会话清掉计 purged；⑨logout 删除该终端的活动与挂起会话并返回删除条数，重复调用返回 0；⑩单终端活动会话数达到 max_active_per_terminal 后，第三张工牌刷卡要按上限拒绝并保留前两个会话；⑪单工牌占用的终端数（活动加挂起）达到 max_terminals_per_badge 后，在新终端刷卡抛 BADGE_TERMINAL_LIMIT；⑫另外两条必须处理：同一工牌在相邻终端连续刷卡只能迁移一处、不得让两台终端都进入活动会话，终端离线超过 offline_grace 后恢复请求必须失败并要求重新刷卡。

硬约束：tap、suspend、resume、logout 与快照全程持锁，同一刷卡事件被多路并发上报时只能开出一个会话，其余按重放返回，opened 与 replays 计数不得错账；快照覆盖 terminals、sessions、seq、counters，恢复后活动与挂起状态、挂起会话剩余 TTL 与去重进度都要与快照一致，结构非法抛 BADGE_SNAPSHOT 且原状态不变。stats 固定返回 taps、replays、opened、suspended、resumed、logouts、purged、refused。

验收：`python3 -m pytest -q tests` 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发刷卡与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: badge_session_switcher
- typeName: BadgeSessionSwitcher
- file: badge_session_switcher.py
