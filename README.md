# batch50-py-game-b-04

## 题面

场景组在开放世界大版本前夜发现层级同步不对：角色挂到载具下后，子节点还按旧父级的世界坐标渲染，载具开走角色留在原地；同一节点每帧被重复标脏，层级遍历时间翻了三倍；更严重的是提交过程中渲染线程读到了半更新的层级，出现一帧模型炸开。提交失败回滚一次后脏标记丢了一半，下一帧不再重算，错位一直保留到重新加载场景。范围是 gsb/batch50-py-game-b-04 的 scene_graph_dirty_sync.py，类 SceneGraphDirtySync，负责场景层级变换的脏标记传播、先父后子重算、双缓冲提交与回滚恢复。

公开接口：SceneGraphDirtySync(*, max_nodes=256)；attach(node_id, *, parent=None, local=(0, 0, 0))；set_local(node_id, *, local)；detach(node_id)；mark_dirty(node_id)；update_world()；commit()；query_world(node_id)；rollback()；snapshot() 与 restore(state)；stats()。拒绝一律抛 SceneGraphError(code, detail)。

故障与边界：①attach 建立父子关系，node_id 唯一、父节点必须存在，local 为三元数值元组，返回 node_id、parent、local、attached，超过 max_nodes 抛 SG_CAPACITY_EXCEEDED，重复 id 抛 SG_DUPLICATE，参数非法抛 SG_INVALID_ARGUMENT；②set_local 修改本地变换并把该节点及整棵子树标脏，返回 node_id、local、dirty 三个字段，dirty 为本次新增的脏节点数；③mark_dirty 同样向下传播，已经脏的节点不重复计数，同一子树重复调用返回 0；④update_world 按先父后子的顺序重算 pending 世界坐标，只有脏节点及其必要祖先参与，父节点未重算时不得先算子节点，返回 recomputed 与 remaining 两个计数；⑤query_world 永远返回最近一次成功提交的世界坐标，从没提交过的节点抛 SG_NO_COMMIT，未知节点抛 SG_UNKNOWN；⑥节点被 detach 后仍可被查询，返回最后一次成功提交的世界坐标，而不是报错或零值；⑦commit 在仍有脏节点时抛 SG_DIRTY_PENDING，成功后代数加一并返回 generation 与 nodes，同时把整帧 pending 一次性写入渲染侧只读缓冲；⑧提交期间渲染侧不得看到半更新层级，必须整帧原子替换，提交过程中的任何异常都不能留下半份数据；⑨detach 返回后序移除的 id 列表，子先父后、同层按挂接顺序，重复或未知 detach 抛 SG_UNKNOWN；⑩rollback 撤销上次提交以来的待提交改动：恢复已提交世界与代数、移除提交后新增的节点并恢复本地变换，返回 generation、restored 与 removed 三个计数，restored 为被回滚的节点数、removed 为被移除的节点数，没有可回滚的提交时抛 SG_NO_ROLLBACK；⑪回滚时脏标记要恢复成提交前的完整集合，不能只回滚已经重算过的节点；⑫快照键为 version、generation、nodes、pending、committed、dirty、modified、stats，深拷贝节点表、pending、committed、脏集合、代数与统计，generation 与统计计数不得为负，恢复非法结构抛 SG_SNAPSHOT_INVALID 且现场不变。

硬约束：双缓冲提交的原子性，渲染侧任何时刻只能看到完整的一代世界坐标；回滚一致性，恢复后代数、已提交世界与脏标记必须回到同一代；同一节点重复标脏只触发一次重算，不能让遍历时间随重复调用增长。stats 返回 nodes、attached、detached、dirty_marks、recomputed、commits、rollbacks。

验收：python3 -m pytest -q tests 必须 15 条全过；不得改测试、跳过、按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: scene_graph_dirty_sync
- typeName: SceneGraphDirtySync
