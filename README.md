# batch50-py-game-a-06-p5

## 题面

战场迷雾这两周在两张新图上连着出岔子，工单已经排到四十多单。第一类是边界：斥候贴着地图左上角绕一圈，玩家的小地图上会多出一片地图外的地形。第二类是叠视野：两名队员并肩推进，其中一人被击杀、视野按规则撤回后，整片区域直接变黑，另一个还站在原地的人也看不见自己脚下。第三类出现在换队伍：玩家中途转到新队伍，刚入队就能看见新队友早先点亮、但当前没有任何人盯着的区域，等于把别人的永久探索记录带了过来。范围是 gsb/batch50-py-game-a-06-p5 的 fog_of_war_explorer.py，类 FogOfWarExplorer，负责单位视野登记、移动、显式揭示，以及按队伍查询当前可见与历史已探索格。

公开接口：FogOfWarExplorer(*, width=32, height=32, max_radius=6, default_radius=2, max_viewers=64)；add_viewer(viewer_id, team, x, y, radius=None)、move_viewer(viewer_id, x, y)、remove_viewer(viewer_id)、reveal_circle(team, x, y, radius)、visibility_at(team, x, y)、cell_info(team, x, y)、visible_cells(team)、explored_cells(team)、viewer_stats(viewer_id)、team_snapshot(team)、snapshot()、restore(state)、stats()。拒绝一律抛 FogError(code, detail)。

故障与边界：①视野按欧氏圆判定，格心距离平方不超过半径平方即覆盖，半径 2 恰好 13 格；②圆形覆盖在地图边缘只算落在网格内的格子，越界坐标一律不写入；③编号与队伍名去空白后不得为空，坐标必须是网格内的整数，越界报 FOG_OUT_OF_BOUNDS，其余参数问题报 FOG_INVALID_REQUEST；④半径取 1 到 max_radius，省略时用 default_radius；⑤同一编号重复登记报 FOG_VIEWER_EXISTS，在场单位超过 max_viewers 报 FOG_CAPACITY_EXCEEDED 且现场不变；⑥每格分别记录当前可见计数与首次揭示代际，代际 0 表示从未揭示，visibility_at 据此返回 visible、explored、hidden；⑦单位移走后原格子转为已探索而不是重新变黑，move_viewer 返回本次新增与失去的可见格数，原地移动返回 0 和 0 但仍计一次移动；⑧remove_viewer 返回释放的可见格数，再次移除报 FOG_UNKNOWN_VIEWER；⑨reveal_circle 供侦察道具使用，只统计首次点亮的格数，重复揭示同一片返回 0；⑩visible_cells 与 explored_cells 只取本队伍的格子，按 x 升序、x 相同按 y 升序；⑪team_snapshot 给出成员、可见格、已探索格与三项计数，成员按编号升序，viewer_stats 里 visible 是该单位自身视野内的格数、seen 是它个人累计点亮过的格数；⑫入队只共享加入之后的当前可见，不把队伍已有的永久探索历史复制给新成员。

硬约束：登记、移动、揭示与移除都在同一把锁内完成，多线程同时移动不同单位时 moves 计数必须与成功调用次数一致，坐标与揭示代际都不能丢；快照固定为 version、gen、grids、viewers、stats 五个键，是深拷贝，restore 校验结构，缺键、版本不符或类型不对报 FOG_SNAPSHOT_INVALID 且现场一格不动，恢复后已探索代际、个人历史与统计继续可用，重启不能把地图打回全黑。网格尺寸、半径与单位数量都有硬上限，单次揭示的遍历量以半径平方为上界，不得整图扫描。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现，不引入第三方库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: fog_of_war_explorer
- typeName: FogOfWarExplorer
