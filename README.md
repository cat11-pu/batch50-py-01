# batch50-py-game-c-05

## 题面

品牌方这周连退了三版成片：同一段时间里左上角同时压着两家的角标，谁也看不清；低优先级的贴片水印没有备选位可用时被直接丢掉，复盘时连降级原因都查不到；有一段水印正好跨过两个片段的接缝，第二段开头又从头淡入一次，观众看到角标闪了一下；运营改了区域顺序之后，之前已经生效的排布还在按老位置出图；片段登记重叠，时间轴怎么都对不上。范围是 gsb/batch50-py-game-c-05 的 watermark_region_planner.py，类 WatermarkRegionPlanner，负责按片段安排水印区间、区域避让、跨片段延续与成片排布，供后期流水线和审片工具共用。

公开接口：WatermarkRegionPlanner(*, default_opacity=0.8)；set_regions(regions)；add_segment(segment_id, *, start, end)；add_slot(slot_id, *, start, end, region, alternatives=(), priority=0, opacity=0.8, fade_in=0)；remove_slot(slot_id)；plan()；conflicts()；apply(plan_id)；at_time(time)；active_plan()；slots()；snapshot、restore、stats。拒绝统一抛 WatermarkError(code, detail)。

故障与边界：①set_regions 收非空且互不重复的区域名并返回注册顺序元组，非法抛 WATERMARK_INVALID，已有槽位后再改区域抛 WATERMARK_REGIONS_LOCKED；②add_segment 要求 segment_id 唯一、start 非负、end 大于 start，区间不得与其他片段重叠，非法抛 WATERMARK_INVALID，重复 id 抛 WATERMARK_SEGMENT_EXISTS，未登记片段时整条时间线视为一个片段、segment_id 为空串；③add_slot 校验起点非负、终点大于起点、区域已登记、alternatives 都是已登记区域且不含主区域、无重复，priority 取 0 到 9 整数、opacity 在 0 到 1 之间、fade_in 为非负整数，非法抛 WATERMARK_INVALID，重复 slot_id 抛 WATERMARK_SLOT_EXISTS；④plan 每次生成 plan-0001 递增的新计划，assignments 按起点、slot_id 升序，同一输入重复规划结果一致但计划号不同；⑤同一片段内时间交叠且请求同一区域的槽位构成冲突，conflicts 返回按起点、slot_id 排序的冲突对并记录交叠区间；⑥规划按优先级从高到低放置，先占主区域，主区域被更高优先级占用时依次尝试 alternatives，改到备选区域的计 relocations；⑦所有备选区域都被占用时保留最高优先级水印并记录降级原因，不得静默丢弃；⑧apply 只接受已生成的计划，未知计划抛 WATERMARK_UNKNOWN_PLAN，生效后 active_plan 返回该计划号，生效前调用 at_time 抛 WATERMARK_NO_PLAN；⑨at_time 返回该时刻覆盖的 assignment 并按区域注册顺序排序，每个区域最多一条，落在所有区间之外返回空元组；⑩跨片段的槽位在第二个片段起标记 continued，相邻片段各出一条 assignment，片段内起止裁剪到片段边界，continuations 统计延续条数；⑪透明度渐变从 fade_origin 起算，有效值等于 opacity 乘以 min(1, (t - fade_origin + 1) / fade_in) 保留三位小数，fade_in 为 0 时等于 opacity，跨片段延续不得重置渐变计时、延续段沿用剩余进度；⑫增删槽位都会让生效计划失效，remove_slot 对未知 id 返回 False；snapshot 返回 {version, regions, segments, slots, plans, active, sequence, stats} 的深拷贝，restore 校验版本、字段类型与统计项齐全，非法抛 WATERMARK_SNAPSHOT_INVALID 且原状态不变；stats 至少含 segments、slots、plans、applied、conflicts、relocations、degraded、continuations。

硬约束：set_regions、add_slot、remove_slot、plan、apply 必须在同一把锁内完成，并发登记后规划不得丢槽、同一时刻同一区域只能有一条最高优先级水印、relocations 与 conflicts 计数必须自洽；快照恢复后区域、片段、槽位、计划、生效计划与全部计数都要在，且不得与调用方共享可变结构。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: watermark_region_planner
- typeName: WatermarkRegionPlanner
