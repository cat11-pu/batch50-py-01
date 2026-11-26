# batch50-py-game-b-05

## 题面

动作组在测试骑马射箭时发现手臂和弓的动画打架：两层动画叠在一起时骨骼明显被拉细，权重全设成 0 后角色直接消失而不是回到待机；同步组里两个跑步循环相位差一格时，角色先反向倒放半圈再追上，看起来像抽搐。编辑器保存再打开后相位和权重全丢，重新打开工程动作直接跳回第一帧。同一套混合树既跑在角色预览窗口，也跑在战斗回放里，回放要求同一时间点每次求值都一致。范围是 gsb/batch50-py-game-b-05 的 animation_blend_tree.py，类 AnimationBlendTree，负责多层动画的权重归一、同步组相位对齐、分层遮罩与姿态求值。

公开接口：AnimationBlendTree(*, default_pose=None)；add_clip(clip_id, *, layer=0, length=1.0, weight=1.0, phase=0.0, bones=None)；remove_clip(clip_id)；set_weight(clip_id, weight)；set_phase(clip_id, phase)；join_sync_group(group, clip_id)；evaluate(time)；set_layer_mask(layer, bones)；pose_of(clip_id, time)；snapshot() 与 restore(state)；stats()。拒绝一律抛 BlendError(code, detail)。

故障与边界：①每个片段的 bones 是骨骼到 (起始值, 结束值) 的映射，按 length 线性插值，length 必须大于 0，weight 落在 0-1，phase 非负，add_clip 返回 clip_id、layer、length、weight、phase、bones（升序元组），重复 clip_id 抛 BLEND_DUPLICATE，set_weight 与 set_phase 返回生效值，bones 为空或值不是二元组抛 BLEND_INVALID_ARGUMENT；②pose_of 返回单片段把 (time + phase) 对 length 取模后的插值结果，不做混合，effective 字段给出取模后的相位；③evaluate 对每根骨骼按参与片段的权重做加权平均后再归一，返回 bones、fallback、normalized，time 为负或非数值抛 BLEND_INVALID_ARGUMENT，同一骨骼上权重大的片段占比更高；④权重为 0 的片段不参与该骨骼的归一，不能把分母抬高；⑤所有片段权重都为 0 时退回 default_pose，返回 fallback=True，而不是输出空姿势；⑥同一状态连续 evaluate 两次必须逐骨骼一致，不依赖调用顺序，也不得把相位对齐的副作用留在第二次求值里；⑦同步组内相位差超过半周期时按取模后的最短路径对齐，不做整圈追赶；⑧同步组要求片段 length 相同，组名为空抛 BLEND_INVALID_ARGUMENT，跨组重复加入抛 BLEND_SYNC_CONFLICT，长度不同抛 BLEND_SYNC_LENGTH，重复加入同一组幂等并返回组内成员升序元组；⑨set_layer_mask 对层设置骨骼白名单，去重后升序返回，空集合、负层号或非法骨骼名抛 BLEND_INVALID_ARGUMENT；⑩遮罩外的骨骼继承上一层已经混合好的权重结果，而不是归零后重新归一；⑪未知片段一律抛 BLEND_UNKNOWN，remove_clip 返回被移除片段记录，参数越界抛 BLEND_INVALID_ARGUMENT；⑫快照键为 version、clips、groups、masks、default_pose、stats，保存片段表、权重、相位、同步组、遮罩、default_pose 与统计，统计计数不得为负，恢复后 evaluate 与恢复前逐骨骼一致，非法结构抛 BLEND_SNAPSHOT_INVALID 且现场不变。

硬约束：权重归一与零权重回退必须逐骨骼成立，不能出现总和为 0 的除零；重复求值确定性，同一份状态任意次 evaluate 结果一致；快照恢复一致性，相位、权重、同步组和遮罩都要还原到同一状态。遮罩按层号从小到大依次生效，上层只覆盖白名单内的骨骼，白名单外保持下层结果。stats 返回 clips、evaluations、fallback_evals、sync_joins、mask_updates。

验收：python3 -m pytest -q tests 必须 15 条全过；不得改测试、跳过、按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: animation_blend_tree
- typeName: AnimationBlendTree
