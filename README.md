# batch50-py-game-c-06

## 题面

录音棚这周连着退单：老磁带转数字化以后，人声尾音里能听到短促的啪声，节奏轨上还有几处被削平的方头，母带师说这些位置原来的瞬态形状全丢了；更麻烦的是同一批素材在两台机器上重跑，修复后的残差数字对不上，质检只能逐条人工复听。处理链路按块推流送进 gsb/batch50-py-game-c-06 的 declick_repair_planner.py，由 DeclickRepairPlanner 负责检测、规划与修复，出问题的就是它。样本是归一化到 -1 到 1 的浮点值，块按到达顺序串行送入，块与块之间不许出现二次接缝。

对外接口：DeclickRepairPlanner(*, threshold=0.5, sample_rate=48000, max_repair_len=64, max_points_per_block=8, merge_gap=2, residual_limit=0.25)；feed_block(block)；detect_clicks()；plan_repair(clicks)；apply_repair(spans)；verify_residual()；set_threshold(value)；set_sample_rate(rate)；set_limits(*, max_repair_len=None, max_points_per_block=None)；committed_blocks()；repair_stats()；snapshot()；restore(state)。异常统一抛 DeclickError(code, detail)，Click 带 start/end/kind/peak，RepairSpan 带 start/end/mode。

要修的地方：一、连续超过 threshold 的样本合成一个事件，两段之间低于阈值的间隔不超过 merge_gap 个样本必须并成一条，超过就分开报；二、长度一到两个样本、峰值未到 0.98 的算短咔嗒，kind 记 click，长于两个样本又没触到 0.98 的响段是正常瞬态，直接放过；三、整段都压在 0.98 以上的平台 kind 记 clip，峰值取段内最大绝对值，事件按起点升序，plan_repair 给 click 出 linear、给 clip 出 envelope，跨度与原事件一致，短咔嗒在两端样本之间线性桥接；四、单条跨度超过 max_repair_len、或同一块内规划点数超过 max_points_per_block，都要整次拒绝，不返回半份结果，已有样本一个都不许动；五、apply_repair 返回本次真正替换的样本数，同一批跨度重复提交必须返回 0；六、verify_residual 逐条给出 start、end 与 residual（修复值相对两端样本连线的累计偏离）以及整体 ok；七、feed_block 遇到非数值样本整块拒绝，块序号从 0 递增；八、threshold 必须落在 (0, 1]、sample_rate 必须为正，越界拒绝；九、committed_blocks 只把块尾落在最后一次修复跨度终点之后一个样本以内的块算作已提交，repair_stats 给出 blocks、samples、clicks、clips、spans、applied、sample_rate、threshold、max_repair_len。

十、削波平台内部没有可用的峰值形状，只能按两侧斜率重建包络，不能简单做线性插值糊过去；十一、修复区间横跨两个处理块时，前块尾部要保留重叠样本供后块接续，后块不得把同一段再修一遍；十二、长度不足最短时长的单样本毛刺只做平滑，不按完整咔嗒替换整段。

硬约束：同一批跨度被多路调用同时提交时，每个样本只能被替换一次，检测、规划、应用三步必须在同一把锁下看到一致状态；快照要能被另一端完整加载，恢复后 committed_blocks、已修复跨度、残差与计数必须和中断前一致，重启后从最后已提交块继续，结构不合法的快照整份拒绝且不动现场。单次修复长度与单块修复点数是硬顶，只能拒绝，不能截断放行。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不许改测试、不许跳过、不许按固定输入写死返回值；并发提交与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-game-c-06
- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: declick_repair_planner
- typeName: DeclickRepairPlanner
- file: declick_repair_planner.py
