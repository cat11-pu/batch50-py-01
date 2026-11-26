# batch50-py-game-c-05-p5

## 题面

手持跟拍的那条素材剪进正片之后，画面在人物走位时左右抽动，快门慢的段落还出现斜向果冻，越靠近画面边缘越明显；导出时又发现四周有黑边，放大补边之后有效分辨率不够，平台判定不达标打了回来。摄影师已经重拍过一遍，抖动依旧，剪辑师换成插件自动修复，边缘黑边照样冒出来。范围是 gsb/batch50-py-game-c-05-p5 的 stabilization_planner.py，类 StabilizationPlanner 负责摄入陀螺仪与光流采样、平滑相机路径、逐帧求裁剪窗、按间隔压缩关键帧并补偿滚动快门。

公开接口：StabilizationPlanner(*, smooth_radius=8, max_samples=4096, min_confidence=0.3, max_scale=1.25)；register_clip(clip_id, width, height, *, fps=60, smooth_radius=None)；ingest_motion(clip_id, samples)；set_rolling_shutter(clip_id, skew_lines)；smooth_path(clip_id, radius=None)；plan_crop(clip_id, out_width, out_height)；keyframe_crop(clip_id, interval)；validate_bounds(clip_id, crop)；committed_keyframes(clip_id)；commit(clip_id, upto_index)；clip_of(clip_id)；stats、snapshot、restore。拒绝操作抛 StabilizationError(code, detail)，错误码统一用 STAB_ 前缀：INVALID_REQUEST、DUPLICATE_CLIP、SAMPLE_LIMIT、INVALID_SAMPLE、UNKNOWN_CLIP、NOT_SMOOTHED、ORDER_VIOLATION、SNAPSHOT_INVALID；stats 返回 clips、samples、planned、keyframes、committed、refuses 六个计数。

故障与边界：①片段宽、高、帧率必须为正，重复 clip_id 拒绝，单片段采样数受 max_samples 硬顶；②运动采样是逐帧的横纵位移与置信度，置信度必须落在 0 到 1 之间，越界整批拒绝而不是丢弃该帧；③空采样列表拒绝，摄入返回真正被接收的条数；④滚动快门偏移以行数表示，不得为负；⑤平滑路径对每帧位移做半径内的滑动平均，半径不传就用片段默认值，首尾不足半径时按实际邻域算，不累积成绝对位置；⑥没有摄入采样的片段不能求平滑路径，没求过平滑的片段不能出裁剪窗；⑦裁剪窗数量与采样数一致，宽高取自请求的输出尺寸；⑧关键帧按间隔抽取，间隔必须为正，抽出的下标从零开始；⑨validate_bounds 判断裁剪窗是否完全落在源画面内，越界返回 False；⑩提交水位只能前进，回退要拒绝，commit 返回新的水位，已提交关键帧数按水位统计；⑪快照深拷贝片段、运动、平滑路径、裁剪轨迹与水位，恢复后全部还在，结构损坏整次拒绝且原状态不变。

两条硬约束：摄入、计划、提交与快照要共用一把锁，别的线程读到的裁剪轨迹必须是完整一版，不能一半新一半旧；采样数、平滑半径、输出缩放比都是硬上限。构图口径另作约定：裁剪窗在画面边缘必须向内收缩，不能靠黑边填充，输出缩放比也不得超过源分辨率上限；滚动快门校正与路径平滑的先后顺序固定，必须先做校正再平滑，反过来会让高频抖动回弹；片段中间置信度骤降时只能冻结当前裁剪轨迹，不能重置到画面中心产生跳变。快照是重启后的续算依据，恢复出来的提交水位要与中断前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发摄入与恢复续算自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: stabilization_planner
- typeName: StabilizationPlanner
