# batch50-py-game-b-09

## 题面

场景组在夜城主街做性能验收时发现静态建筑的阴影一直在重画，帧率比预期低一截；把主光源挪一下，好几个物件的阴影会整帧发黑；切 LOD 之后部分物件的阴影还错位了；缓存槽位用满以后，画面里的阴影开始闪。范围是 gsb/batch50-py-game-b-09 的 static_shadow_cache.py，类 StaticShadowCache，负责登记静态物体、在对象变换或材质或 LOD 变化时标脏、按帧复用渲染结果、容量不足时淘汰本帧没用的槽位；这些入口目前在代码里没有任何行为，一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：StaticShadowCache(*, capacity=4)；register(object_id, *, transform=(0.0, 0.0, 0.0), material="default", lod=0)、tick()、acquire_slot(object_id)、release_slot(object_id)、refresh(object_id)、invalidate(object_id, reason="transform")、lookup(object_id)、resize(capacity)、stats()、snapshot()、restore(state)。拒绝一律抛 ShadowCacheError(code, detail)。

故障与边界：①register 要求 object_id 去空白后非空且不得重复、transform 是 3 个有限数值、material 去空白后非空、lod 是非负整数，任一项不合规报 SHADOW_INVALID_INPUT；未登记对象一律报 SHADOW_UNKNOWN_OBJECT；②tick 把帧号加一并返回新帧号，初始帧号为 0，本帧已用的标记只在 tick 时重置；③acquire_slot 在对象已有槽位时直接复用并记一次使用，没有槽位时取编号最小的空闲槽位，没有空闲槽位时淘汰本帧没使用过的对象里最久未使用的那个（按使用序号升序，序号相同按对象 id 升序），被淘汰对象的槽位立即释放且内容作废，本帧全都用过则报 SHADOW_CAPACITY_EXCEEDED 且一个都不淘汰；④refresh 先确保槽位（没有就按 acquire 的规则分配），内容脏或从未渲染过就重绘一次，generation 加一、renders 加一、rendered 为 True，不脏则直接复用、reuse_hits 加一、rendered 为 False；返回 object_id、slot、frame、generation、payload、rendered，payload 固定含 object、transform、material、lod、generation 五个键；⑤invalidate 只接受 transform、material、lod 三种原因，其他报 SHADOW_INVALID_INPUT，第一次标脏返回 True、已经是脏的再标返回 False，每次被接受的调用都计入 invalidations，同一帧内多次标脏只在下一次 refresh 时重绘一次；⑥release_slot 释放已有槽位返回 True，本来没有槽位返回 False，释放后对象仍登记但内容作废，下次 acquire 或 refresh 重新分配并重绘；⑦lookup 不改动计数与使用顺序，返回 slot、dirty、generation、last_frame、uses、rendered，没有槽位时 slot 为 None；⑧resize 扩容只改容量、不重建不淘汰并返回 0，缩容按与 acquire 相同的规则淘汰并返回淘汰数，缩到比本帧在用槽位还少时报 SHADOW_CAPACITY_EXCEEDED 且容量与槽位都不变，容量小于 1 或非整数报 SHADOW_INVALID_CAPACITY；⑨被淘汰的对象在同一帧内再次请求时必须拿到与上次不同的槽位，不许沿用被淘汰前的槽位下标，也不许直接捡刚刚释放的那个槽位；⑩LOD 变化触发的失效只更新内容，不改变对象在缓存里的使用优先级，不许把它顶成最近使用；⑪快照固定为 version、capacity、frame、objects、slots、entries、counters、use_seq 八个键，整体是深拷贝，restore 校验结构（slots 与 entries 必须互相一致、last_frame 不得超过 frame），缺键、版本不符或类型不对报 SHADOW_SNAPSHOT_INVALID 且原状态不被改动；⑫恢复后帧号、槽位分配、脏标记、generation、使用顺序与各项计数都要继续可用，重启不能把干净对象当成全脏，也不能把沿用旧顺序的淘汰次序打乱。

硬约束：同一对象被多路线程在同一帧里并发 refresh 时只能真正渲染一次，其余线程拿到同一份 generation 与 payload，renders 不得翻倍，也不许两个对象分到同一个槽位；快照与恢复要在同一把锁内完成，恢复失败时帧号、槽位、脏标记与计数都不留半截改动；容量是硬上限，任何时刻已分配槽位数不得超过 capacity，正在本帧使用的槽位不得被淘汰。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；题面点到的每一项都要落到代码行为上；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: static_shadow_cache
- typeName: StaticShadowCache
