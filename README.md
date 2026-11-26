# batch50-py-game-a-10-p5

## 题面

新副本上线第二天，可破坏城墙就出了三类结算事故。第一类在环形回廊：玩家只炸断了一段支撑，整圈回廊连着外侧塔楼一起塌了，而按图纸本该还能撑住。第二类是连爆：坍塌飞出的碎石对已经倒下的构件又扣了一遍耐久，结算流程在里面绕不出来，房间直接超时。第三类是修复：工程兵把一根承重柱修回满耐久，同区域几小时前已经塌掉的半面墙跟着一起立了回来。范围是 gsb/batch50-py-game-a-10-p5 的 destruction_support_graph.py，类 DestructionSupportGraph，负责构件登记、伤害累计、支撑判稳、区域坍塌、掉落结算与结构重置。

公开接口：DestructionSupportGraph(*, max_components=256, max_collapse=32, default_durability=100, secondary_damage=15)；register_structure(structure_id, components, edges, *, region=None)、apply_damage(structure_id, component_id, amount)、evaluate_support(structure_id)、collapse_region(structure_id, component_id)、settle_loot(structure_id)、repair(structure_id, component_id)、reset(structure_id=None)、component_of(structure_id, component_id)、durability_of(structure_id, component_id)、pending_loot(structure_id)、structures()、snapshot()、restore(state)、stats()。拒绝一律抛 GraphError(code, detail)。

故障与边界：①构件以 component 字段标识，同一结构内不得重复，edges 里出现未知构件或自环视为非法，没有落地构件的结构也非法，统一报 GRAPH_INVALID_REQUEST；②结构编号去空白后不得为空且不得重复，重复报 GRAPH_STRUCTURE_EXISTS，单结构构件数超过 max_components 报 GRAPH_CAPACITY_EXCEEDED 且不登记；③耐久取正整数，省略时用 default_durability，非正或非整数报参数错误，伤害 amount 同样只接受正整数；④apply_damage 扣减耐久，降到 0 即标记 destroyed 并从支撑图摘除，再次伤害或修复已毁构件报 GRAPH_COMPONENT_GONE；⑤未知结构报 GRAPH_STRUCTURE_UNKNOWN，未知构件报 GRAPH_COMPONENT_UNKNOWN；⑥evaluate_support 只返回仍然存活、且无法沿边到达任何落地构件的构件，按编号升序，落地构件自身永远稳定；⑦collapse_region 先移除目标构件，再按失稳集合逐个塌落，顺序为目标优先、其余按编号升序，总数不超过 max_collapse，超出部分计入 pending 留在场上；⑧每个塌落构件产出一条掉落行，含 item、material、quantity 与 from，material 取构件材质，item 为材质名加 -rubble，quantity 固定为 1，掉落进入待结算队列；⑨坍塌对仍然存活且与塌落构件相邻的构件造成 secondary_damage 点二次伤害，被打到 0 的计入 secondary_destroyed；⑩settle_loot 按塌落顺序返回并清空待结算队列，空队列返回空列表，repair 只把存活构件恢复到耐久上限；⑪环形支撑局部断开后仍可能整体稳定，判稳必须按连通分量到地基的可达性，不能按局部连接数；⑫坍塌砸中的二次伤害不得反向破坏已经坍塌的构件，构件修回耐久上限时只能恢复自身，不能连带复活同区域已坍塌构件。

硬约束：apply_damage 与 collapse_region 共用一把锁，多线程同时打同一构件时耐久扣减不能丢，destroys 只能发生一次，collapse_region 必须整段完成再释放锁，中途不得让别的线程看到半塌状态；快照固定为 version、structures、stats 三个键，深拷贝，restore 校验版本与结构，缺键或类型不对报 GRAPH_SNAPSHOT_INVALID 且现场不动，恢复后已毁构件、剩余耐久、待结算掉落与统计继续可用，重启不能让塌掉的墙重新立起来。构件数、单次坍塌数与掉落下发量都有硬上限，settle_loot 必须按下标顺序出队，不得反复遍历全结构。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现，不引入第三方库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: destruction_support_graph
- typeName: DestructionSupportGraph
