# batch50-py-safety-c-19

## 题面

攻防演练前一周，红队拿着我们的攻击路径平台复盘，发现三处明显不对。一处是明明两跳就能打穿，平台却给出绕四跳的方案，因为查询按跳数排了序而不是按成本；另一处是资产下架之后，前一天缓存的路径还在返回，红队照着打到一个已经不存在的机器；还有一处更烦人，图上出现循环关系时查询直接卡住不返回，值班同事只能重启服务。范围是 gsb/batch50-py-safety-c-19 的 attack_path_pruner.py，类名 AttackPathPruner，负责资产关系图的增删、按成本返回前几条可达路径、节点移除后的增量缓存失效，以及图规模的硬上限。

公开接口：AttackPathPruner(*, max_edges=200, max_cache_entries=128)；add_edge(src, dst, *, cost, technique="")；remove_edge(src, dst) -> int；remove_node(node) -> int；shortest_to(target, *, k=3) -> list[Path]；invalidate(*, node=None) -> int；nodes()；edges()；cache_info()；stats()；snapshot()；restore(state)。Path 是冻结数据类，带 nodes 元组、cost 与 techniques 元组。拒绝时抛 PrunerError(code, detail)。

故障与边界：①边两端不能为空，否则 PRUNER_BAD_NODE；成本必须是正整数，字符串、零与负数都拒，否则 PRUNER_BAD_COST；自环拒，PRUNER_SELF_LOOP；同一起止重复加边拒，PRUNER_DUPLICATE_EDGE。②边数到达 max_edges 后新增直接拒绝，PRUNER_EDGE_LIMIT，已有边与节点一条都不许丢。③shortest_to 只从没有任何入边的入口资产出发，返回成本升序的前 k 条路径，路径里的节点与可利用手法要和边一一对应。④k 必须是 1 到 10，越界抛 PRUNER_BAD_LIMIT；目标节点不存在抛 PRUNER_UNKNOWN_NODE；节点存在但不可达返回空列表。⑤跳数少的方案不一定更便宜，排序只看累计成本。⑥缓存按目标节点记账，命中与未命中分别计数，cache_info 给出 entries、hits、misses、invalidations 四项。⑦invalidate(node=...) 只丢与该节点相关的缓存项，invalidate() 清空全部，两者都返回本次丢掉的条数。⑧remove_node 连带删掉全部入射与出射边并返回边数，节点不存在抛 PRUNER_UNKNOWN_NODE；remove_edge 成功返回 1，边不存在抛 PRUNER_UNKNOWN_EDGE。⑨加边、删边、删节点都必须让受影响目标的缓存立即失效，不能让旧路径继续被返回。⑩图中存在环时返回的路径不得包含重复节点。⑪起止相同、成本也相同的多条路径要按节点序列字典序稳定排序，同一张图重复查询结果一致。⑫路径返回前做前缀去重，同一节点序列只出现一次，作为其它结果前缀的更短路径不再重复返回。

硬约束：图结构与缓存的写入必须在同一把锁内完成，删节点要么整条边集一起消失要么完全不生效；缓存条目受 max_cache_entries 硬顶，超过就淘汰最久未使用的目标，不得无界增长；快照与活动状态完全脱钩，恢复后节点、边与计数原样回来，缓存一律不落快照并按需重建，非法快照抛 PRUNER_SNAPSHOT_INVALID 且不改动现有数据。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发查询与删节点自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: attack_path_pruner
- typeName: AttackPathPruner
