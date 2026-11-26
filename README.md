# batch50-py-game-b-10-p5

## 题面

战斗组这周被动画问题拖住：加法层叠上去以后整体姿态被过度放大，骨骼冲破限位；遮罩里没列出的骨骼被写成单位四元数，下层动作整段消失；删掉中间一层战斗姿态后，剩下两层的混合顺序变了，手臂抖了一下；回滚到上一次快照，层号和权重没回来，只能重配；动画验收要求同一段输入的姿态逐帧一致，回放里不能出现层顺序漂移。范围是 gsb/batch50-py-game-b-10-p5 的 pose_blend_stack.py，类 PoseBlendStack，在骨骼姿态上叠加基础层、覆盖层和加法层，每层带骨骼遮罩、权重与混合模式，按归一化权重输出姿态并保留有限历史。

公开接口：PoseBlendStack(*, max_layers=8, max_history=8, max_mask_bones=64)；add_layer(layer_id, *, mode="override", weight=1.0, mask=None)；set_weight(layer_id, weight)；set_mask(layer_id, mask)；push_pose(layer_id, pose)；evaluate()；remove_layer(layer_id)；layer_state(layer_id)；layers()；set_limits(bone, low, high)；history()；snapshot()；restore(state)；stats()。姿态以骨骼名到四元数 (x, y, z, w) 的映射表示，所有拒绝统一抛 PoseError(code, detail)。

故障与边界：①层号不得为空，mode 只能是 override 或 additive，weight 为非负数，mask 为骨骼名到 0 到 1 的映射，重复层号报 POSE_LAYER_EXISTS，层数超过 max_layers 报 POSE_LAYER_LIMIT，遮罩骨骼数超过 max_mask_bones 报 POSE_MASK_LIMIT，其余参数问题报 POSE_INVALID_REQUEST；②push_pose 的四元数必须是四个数值分量且模长不为零，内部归一化，空骨骼名或非映射报 POSE_INVALID_REQUEST，坏四元数报 POSE_INVALID_POSE，未知层号报 POSE_UNKNOWN_LAYER；③覆盖层按加入顺序依次叠加，同一骨骼上各有效权重先归一化，再按顺序做球面插值，权重为零的层不参与归一化；④同一骨骼同时被多层覆盖时权重越大越靠近该层姿态，单层身份姿态输出原样；⑤遮罩值会缩放该层的有效权重，遮罩里未列出的骨骼保持下层结果，权重为零的遮罩骨骼不得被写成单位四元数；⑥加法层不参与权重归一，只在覆盖层结果上按权重叠加，叠加后按骨骼限位钳制；⑦set_weight 与 set_mask 立即影响下一次求值，非法值报 POSE_INVALID_REQUEST 且不改原状态；⑧remove_layer 只删指定层，剩余层顺序不变；移除中间层后剩余层的混合顺序不能改变，快照恢复要还原层 ID 与权重；⑨evaluate 返回 revision 与 pose，revision 每次加一，history 只保留最近 max_history 条，超出上限时丢最旧的一条，每条含 revision 与 pose；⑩layers 按加入顺序返回，layer_state 返回 layer_id、mode、weight、mask、pose，初始 pose 为空映射，未知层号在查询、改权重、改遮罩、推姿态时一律报 POSE_UNKNOWN_LAYER；⑪snapshot 返回 {"schema","layers","history","stats"} 深拷贝，layers 为按层序的列表并保存 layer_id、mode、weight、mask、pose，restore 结构非法报 POSE_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 layers_added、layers_removed、poses_pushed、evaluations、weight_updates、mask_updates。

硬约束：多线程求值必须按层序稳定，evaluate 与 set_weight、push_pose 互斥，暂停时权重渐变冻结在最后一次写入值；重启恢复后历史与计数一致且不与调用方共享结构；层数、历史条数与遮罩骨骼数都是硬顶，移除层不得改变剩余层顺序。

验收：python3 -m pytest -q tests 的 15 条用例必须全部通过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: pose_blend_stack
- typeName: PoseBlendStack
