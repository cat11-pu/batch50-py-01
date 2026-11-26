# batch50-py-game-b-08

## 题面

建筑组把高面数网格交给程序化减面，验收时出了三类问题：屋顶的脊线被折出豁口，UV 缝两侧的顶点被并进内部导致贴图裂开；同一份网格连跑两次，折叠顺序和收敛面数都不一样；还有几栋楼离目标差一大截就停工，日志只剩空转。范围是 gsb/batch50-py-game-b-08 的 mesh_decimation_planner.py，类 MeshDecimationPlanner，负责按折叠代价排队、锁定材质边界与 UV 缝、按轮次折叠并在目标不可达时报告实际可达面数；这些入口目前在代码里没有任何行为，一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：MeshDecimationPlanner()；load(mesh_id, vertices, faces)、set_target(faces)、lock_boundary(vertices=None)、edge_cost(left, right)、plan()、apply_round()、report()、rollback(rounds)、stats()、snapshot()、restore(state)。拒绝一律抛 MeshPlanError(code, detail)。

故障与边界：①load 要求 mesh_id 去空白非空、顶点至少 4 个且每个是 3 个有限数值、面至少 1 个且每个面是 3 个互不相同的合法下标，任一项不合规报 MESH_INVALID_INPUT 且不改动已加载网格；返回摘要含顶点数、面数、边界顶点（只被一条边引用的顶点，升序）与 locked（为 0）；②未 load 时 plan、set_target、lock_boundary、edge_cost、apply_round、report、rollback、stats、snapshot 一律报 MESH_NO_MESH；未设目标时 apply_round 报 MESH_NO_TARGET；③set_target 只接受 1 到当前面数减一之间的整数，否则报 MESH_INVALID_TARGET；面数已到目标再 apply_round 报 MESH_TARGET_REACHED；④折叠固定让下标较小的顶点保留、另一个并入，保留端坐标取两端中点（各分量平均，6 位小数）；edge_cost 返回两端当前坐标的平方距离（6 位小数），顶点不存在或两端相同报 MESH_INVALID_INPUT；⑤plan 返回（代价，保留端，被并端）三元组，按代价升序、再按两端下标升序，只列当前可折叠的边；同一网格两次 plan、两个实例对同一网格的 plan 必须逐项一致；⑥lock_boundary 省略参数时锁定 load 时检测到的全部边界顶点，传入下标逐个校验后并入，返回累计锁定数；锁定边界上的折叠只允许合并到同类边界顶点，不允许把边界顶点并入内部顶点；⑦折叠不得产生非流形边（一条边被超过两个面共用）、退化面、重复面，也不得让还活着的顶点变成不参与任何面的孤点；⑧apply_round 取当前 plan 第一条执行一轮，返回轮次、保留端、被并端、代价、折叠前后面数与剩余顶点数；每轮都按当前坐标与拓扑重算代价和顺序，不许沿用上一轮排好的队列；⑨目标不可达时 report 的 reachable 给出当前还能实际减到的面数，不许空转；plan 为空时 apply_round 报 MESH_NO_CANDIDATE 并在 detail 带当前面数与目标面数；⑩rollback 回到第 n 轮结束后的状态（n 为 0 即刚 load 完），越界或负数报 MESH_ROLLBACK_OUT_OF_RANGE；回滚后重新 plan 必须按回滚后的坐标与拓扑重建代价，不许复用回滚前的队列；之后的 apply_round 从第 n+1 轮继续；⑪快照固定为 version、mesh_id、vertices、faces、locked、boundary、target、history、counters 九键，history 逐轮保存坐标与面，整体深拷贝，restore 校验结构（history 末项须与当前状态一致），缺键、版本不符或类型不对报 MESH_SNAPSHOT_INVALID 且原状态不被改动；⑫恢复后目标、锁定、轮次与历史都要继续可用，重启后可直接回滚到任意已应用轮次。

硬约束：同一网格同一目标的折叠顺序与每轮代价必须逐项可复现，不得依赖字典或集合的遍历顺序；面数预算是硬约束，每轮只折一条边，达到目标立即停手；快照与恢复在同一把锁内完成，恢复失败时网格、锁定、目标与历史都不留半截改动；同一实例上的 plan 与 apply_round 并发调用只能串行生效，不许两条折叠基于同一份旧状态各折一次。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；题面点到的每一项都要落到代码行为上；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: mesh_decimation_planner
- typeName: MeshDecimationPlanner
