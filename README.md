# batch50-py-game-b-02

## 题面

动画组这周的反馈集中在雪山关卡的披风：同一帧里近处主角的披风抖得正常，远处背景布却整块静止，看起来像被冻住；帧率掉到 30 时披风直接跳变，越靠近镜头的布反而先不动了。更麻烦的是断点续算：美术在编辑器里暂停后恢复，布料位置和暂停前对不上，重新打开工程时碰撞查询还沿用了上一帧的缓存，出现披风穿过坐骑的穿模事故。同一套调度同时跑在编辑器预览和实机两端，编辑器暂停、实机低帧率两种场景都必须保一致。范围是 gsb/batch50-py-game-b-02 的 cloth_sim_scheduler.py，类 ClothSimScheduler，负责多块布料的子步预算分配、固定步长推进、解绑回写与断点恢复。

公开接口：ClothSimScheduler(*, fixed_step=1/120, substep_budget=8, damping=2.0)；register(cloth_id, *, vertices, pinned=(), rest=None, distance=1.0, visible=True)；unregister(cloth_id)；set_budget(substeps)；step(dt)；state_of(cloth_id)；positions_of(cloth_id)；detach(cloth_id)；collision_batch()；snapshot() 与 restore(state)；stats()。拒绝一律抛 ClothError(code, detail)。

故障与边界：①distance 不超过 2 归为 near，不超过 6 归为 mid，其余为 far，不可见布料不参与子步，register 返回 tier、attached、frame 等字段，重复 cloth_id 抛 CLOTH_DUPLICATE，参数非法抛 CLOTH_INVALID_ARGUMENT，分级只影响预算分配顺序，不改变每块布自己的阻尼与回弹参数；②step 把 dt 累加后按 fixed_step 取整执行，返回 frame、requested、executed、throttled、accumulator，余量留到下一次，dt 非正或非数值抛 CLOTH_INVALID_DT；③单帧执行的子步总数不超过预算，且每块可见布料至少分到 1 个子步，各布料 last_substeps 之和等于本帧 executed，不允许整块跳过；④预算比可见布料数还少时抛 CLOTH_BUDGET_TOO_SMALL，本帧一块布都不推进；⑤预算不足时优先降低远距离布料的子步数，近距离布料的步长保持不变；⑥state_of 返回 frame、attached、tier、visible、last_substeps、total_substeps 与当前位置，未知布料抛 CLOTH_UNKNOWN；⑦pinned 顶点经过任意多子步后位置不变；⑧detach 把顶点状态回写到宿主并返回 vertices、frame 与从 1 递增的 release_order，重复解绑抛 CLOTH_ALREADY_DETACHED，宿主网格顶点数要同步更新；⑨未解绑直接 unregister 抛 CLOTH_STILL_ATTACHED，移除后返回 cloth_id、release_order 与 removed=True，再查抛 CLOTH_UNKNOWN；⑩collision_batch 按 AABB 相交做传递合并，批次内 cloth id 升序、批次之间按最小 id 排序，每批为含 batch 与 cloths 的字典，忽略不可见与已解绑布料；⑪快照包含 fixed_step、damping、budget、frame、accumulator、布料表与统计，恢复非法结构抛 CLOTH_SNAPSHOT_INVALID 且现场不变；⑫set_budget 只接受 1-64 的整数，越界抛 CLOTH_INVALID_BUDGET，成功时返回生效预算，stats 返回 frames、substeps、registrations、detaches、collisions、throttled_frames。

硬约束：固定步长与快照一致性，恢复后继续推进必须与不中断时逐顶点一致，包括累加余量与已执行子步数；预算总量不可突破且不允许整块跳过，碰撞查询按批合并，同一批只计算一次。步进必须串行，同一帧内不允许两个调用者交错修改累加器；恢复快照时上一帧的碰撞缓存必须整体作废重建，不得沿用旧批次。解绑顺序必须稳定可复现，多次运行得到同一份释放序列。

验收：python3 -m pytest -q tests 必须 15 条全过；不得改测试、跳过、按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: cloth_sim_scheduler
- typeName: ClothSimScheduler
