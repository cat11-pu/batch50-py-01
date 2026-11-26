# batch50-py-game-b-07-p5

## 题面

特效组这周收到一串投诉：角色传送之后拖尾没有断开，一条长条横穿整个场景；发射器每帧都在推样本，历史环满了以后整段拖尾突然从中间消失，看不出是哪一段被挤掉；粒子预算紧张时构建直接把历史头部删掉，条带开头跳了一截；维护重启后拖尾从当前帧重新长出来，和战斗录像对不上；验收时美术只认录像里的拖尾形状，任何一段缺失都算返工。范围是 gsb/batch50-py-game-b-07-p5 的 particle_trail_builder.py，类 ParticleTrailBuilder，为每个发射器维护采样历史环，按最小间距与最大时长重采样，生成朝向相机的三角条带，并处理断点、渐隐与全局顶点预算。

公开接口：ParticleTrailBuilder(*, teleport_distance=1000.0, vertex_budget=4096, max_emitters=16)；register_emitter(emitter_id, *, capacity=64, max_age=2.0, min_distance=0.1, priority=0)；remove_emitter(emitter_id)；push_sample(emitter_id, *, position, time, width=1.0, color=(1,1,1,1))；build_ribbon(emitter_id, *, budget=None)；break_trail(emitter_id, *, reason="manual")；set_budget(vertex_budget)；segments(emitter_id)；emitter_state(emitter_id)；emitters()；snapshot()；restore(state)；stats()。所有拒绝统一抛 ParticleError(code, detail)。

故障与边界：①发射器编号去两端空格后不得为空，capacity 至少 2，max_age 与 min_distance 必须为正，重复注册报 PARTICLE_EMITTER_EXISTS，超过 max_emitters 报 PARTICLE_EMITTER_LIMIT；②push_sample 的位置为二元坐标、time 不早于上一帧、width 为正、color 为四个 0 到 1 分量，违规报 PARTICLE_INVALID_REQUEST，未知发射器报 PARTICLE_UNKNOWN_EMITTER；③历史环满后挤掉最旧样本并计入 dropped_capacity，保留样本仍按时间升序，样本颜色与宽度随样本一起保留，emitter_state 返回 emitter_id、capacity、max_age、min_distance、priority、generation、segment_count、sample_count 与 samples，samples 为按时间升序的元组；④采样间距小于最小间距时只更新末样本的宽度与颜色，不新增顶点，避免退化三角形；⑤发射器瞬移超过 teleport_distance 时必须断开并新开一段，不能把两段用长条带连起来；⑥break_trail 显式开新代际并返回新代际号，segments 只列有样本的代际，每项含 generation 与 sample_count；⑦build_ribbon 只保留最新时间往前 max_age 内的样本，过期样本删除并计入 expired_samples；⑧每个样本出两个顶点，格式为 (x, y, u)，左右各偏移半个宽度，u 取 0 与 1，相邻样本成两个三角形，单个样本或空发射器不产三角形，build_ribbon 返回 vertices、vertex_count、triangles、segments 与 truncated，vertices 与 segments 以元组返回；⑨全局顶点预算不足时按发射器优先级截断尾部，不能删除整段历史导致条带头部跳变；⑩set_budget 只接受正整数，remove_emitter 后该编号再访问报 PARTICLE_UNKNOWN_EMITTER，emitters 按优先级降序、同优先级按编号升序；⑪snapshot 返回 {"schema","emitters","budget","stats"} 深拷贝，restore 结构非法报 PARTICLE_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 registered、removed、samples、dropped_capacity、expired_samples、breaks、builds、truncated_builds。

硬约束：同一发射器的推样本与构建必须串行，多线程推样本不得丢样本或把时间顺序写乱，构建时不得就地打乱样本顺序；重启恢复后历史环、代际、上次采样位置与预算都要在，且不与调用方共享结构；发射器数与每环容量、全局顶点预算都是硬顶，断带与过期清理不得留下空壳。

验收：python3 -m pytest -q tests 的 15 条用例必须全部通过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: particle_trail_builder
- typeName: ParticleTrailBuilder
