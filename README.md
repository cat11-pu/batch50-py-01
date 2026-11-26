# batch50-py-game-c-01-p5

## 题面

新版本播放器接上变速不变调以后，鼓组在 1.5 倍速下每隔几十毫秒就有一声咔哒，2.0 倍速时整段人声发虚、齿音散成一片，长片段播到尾部还会少一截；同一段立体声素材在左右声道上听出先后错位，声像像被推开。问题集中在 gsb/batch50-py-game-c-01-p5 的 time_stretch_planner.py，类 TimeStretchPlanner 负责片段登记、变速计划、逐帧对齐搜索与重叠相加。现场反馈换成短采样、提高倍率后问题更明显，制作人已经拒绝在这套链路上出片。

公开接口：TimeStretchPlanner(*, frame_size=1024, max_search_window=512, max_overlap=256, max_clips=64)；register_clip(clip_id, sample_rate, channels, source_samples, *, target_ratio=1.0, search_window=None, overlap=None)；plan_stretch(clip_id, target_ratio=None)；next_frame(clip_id)；drain(clip_id, limit)；pending(clip_id)；rendered_samples(clip_id)；seam_count(clip_id)；cancel(clip_id)；clip_of(clip_id)；stats、snapshot、restore。拒绝操作抛 TimeStretchError(code, detail)，错误码统一用 TIME_STRETCH_ 前缀：INVALID_REQUEST、DUPLICATE_CLIP、INVALID_RATIO、WINDOW_TOO_LARGE、OVERLAP_TOO_LARGE、CLIP_LIMIT、NO_FRAME、CLIP_CANCELLED、SNAPSHOT_INVALID。

故障与边界：①采样率、声道数、源采样数必须为正整数，目标比率限定在 0.25 到 4.0 之间，任何一项越界都要在登记阶段拒绝，不能留到出帧时才报；②同一个 clip_id 重复登记必须拒绝，登记总数受 max_clips 硬顶，超出的片段不许顶掉已有片段；③search_window 与 overlap 各有上限，超限直接拒绝，不允许悄悄截断成上限值；④分析步长取 frame_size 减 overlap，合成步长按比率取整，帧数按源采样数除以分析步长向上取整，三者要能互相印证；⑤plan_stretch 传入的比率只作用于本次计划，片段登记时的比率保持不变，重复规划不许累积放大；⑥帧序号从零递增，源偏移按分析步长走，输出偏移按合成步长走，首帧不带接缝，之后每帧都要记一次接缝；⑦帧数用尽后继续取帧必须报错，pending 归零，不能返回最后一帧的副本；⑧drain 一次取出的帧数不得超过 limit，limit 非正直接拒绝，取出的帧仍按序号升序；⑨cancel 之后该片段不得再出帧，重复取帧报已取消，取消计数只加一次，cancel 返回已合成样本数，取消时已经合成出来的样本要保留，续接同一片段得接着往下算，不许从头重算；⑩快照要深拷贝片段、计划与渲染进度，恢复后待处理帧数、接缝计数、取消状态都要在，结构损坏时整次拒绝且原状态一个字节都不许动；⑪stats 返回 clips、planned、frames、seams、cancelled 五个计数，分别对应片段数、已计划数、已出帧数、接缝数与取消数，要和实际调用次数对得上。

两条硬约束：同一片段的取帧、取消、快照三类调用要从同一把锁进出，任何时刻读到的进度必须停在完整帧边界上，别的线程不能看到半帧；帧数、片段数、搜索窗与重叠长度都是硬上限，超限只能拒绝。尾部与多声道相位另有验收要求：尾帧不足一个分析帧要按零填充，最终输出采样数必须精确等于目标时长，不能多也不能少；多声道必须共用同一个对齐偏移，逐声道各自搜索会让声像漂移，混音时定位全乱。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发取帧与恢复续算自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: time_stretch_planner
- typeName: TimeStretchPlanner
