# batch50-py-game-a-01-p5

## 题面

围甲仲裁连出单：撤手后局面回开局、提掉的子冒回来；棋钟判了超时仍接受落子；数目法与手工差三目半。范围是 gsb/batch50-py-game-a-01-p5 的 weiqi_rule_arbiter.py，类 WeiqiRuleArbiter，管棋盘气、提子、劫争、合法手、数目结算与双方读秒，坐标 (row, col) 0 基。

公开接口：place_stone(color, coord) 返回 MoveRecord；pass_turn、resign、undo_request；tick_clock、pause_clock、resume_clock、clock_state；score、snapshot、restore、stats，拒绝抛 WeiqiError(code, detail)。

故障与边界：①落子先校占用再判手数：非法颜色 WEIQI_INVALID_COLOR、越界 WEIQI_POINT_OFF_BOARD、已占 WEIQI_POINT_OCCUPIED、非当前手方 WEIQI_TURN_ORDER；②提子后仍无气判 WEIQI_SUICIDE；③提子按棋串移除，坐标排序进 captured；④劫争按历史局面哈希比对，不得只比上一手，隔一手后同形可落，立即复原上一手报 WEIQI_KO；⑤两次 pass 终局，此后落子 WEIQI_GAME_OVER；resign 终局给 winner 与 reason；⑥数目法给双方 stones、territory、total，白加 komi，双色共触空区中立；⑦主时间用尽进读秒，扣满一期消耗并重置，读秒用尽该方超时、棋局立即终局并按终局局面结算；⑧暂停只冻结暂停方，另一方 tick 照常；⑨撤销只认最近一手、由该手执子方发起，不得跨越已确认劫争；⑩snapshot 深拷贝，restore 非法报 WEIQI_SNAPSHOT_INVALID，原局面不变。

硬约束：落子、撤销与时钟操作串行，同一交叉点或手序的并发落子只有一个成功；快照恢复后棋盘、手数、提子、历史与双方时钟都在且不与调用方共享结构，stats 含 moves、captures、refused、undos。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: weiqi_rule_arbiter
- typeName: WeiqiRuleArbiter
