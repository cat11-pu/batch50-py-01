# batch50-py-game-c-04-p5

## 题面

一首抒情歌进棚混音之后，主唱的高音句尾被修成了机械的阶梯感，换气口和齿音处干脆被拉到上一个音，听起来像有人替她唱了一个八度；同一条 take 修完整体音色发闷，近讲的气声细节全丢了，时长还短了一小截。录音师把修正幅度调到最小也没用，问题出在修正计划本身，混音师现在只能逐句手工画曲线，交期已经拖了两天。范围是 gsb/batch50-py-game-c-04-p5 的 pitch_correction_planner.py，类 PitchCorrectionPlanner 负责逐帧音高轨迹、按调式音阶吸附、限制修正速率并保持共振峰与原始时长。

公开接口：PitchCorrectionPlanner(*, hop=256, sample_rate=48000, confidence_floor=0.5, max_semitones_per_second=1.5, max_frames=4096)；register_take(take_id, sample_rate, *, hop=None, preserve_formant=True)；analyze_pitch(take_id, frames)；set_scale(take_id, root, mode="major")；plan_correction(take_id)；correction_curve(take_id)；apply_segment(take_id, start_frame, end_frame)；committed_frames(take_id)；take_of(take_id)；confidence_at(take_id, index)；stats、snapshot、restore。analyze_pitch 返回浊音帧数，plan_correction 返回点数、最大偏移与所用音阶。拒绝操作抛 PitchError(code, detail)，错误码统一用 PITCH_ 前缀：INVALID_REQUEST、DUPLICATE_TAKE、INVALID_FRAME、INVALID_MODE、NOT_ANALYZED、ALREADY_COMMITTED、SNAPSHOT_INVALID；stats 返回 takes、analyzed、voiced、planned、committed、refuses 六个计数。

故障与边界：①采样率与帧移必须为正，重复 take_id 拒绝，单条 take 的帧数受 max_frames 硬顶；②逐帧输入是基频（MIDI 半音值）与置信度，置信度必须落在 0 到 1 之间，基频不得为负，出现非法帧整批拒绝而不是跳过；③置信度低于 confidence_floor 的帧算清音，统计里只把浊音帧计入 voiced；④新 take 默认根音 0、major 调式，调式只认 major 与 minor，根音取 0 到 11，其它一律拒绝，返回的音阶按音高类升序排列；⑤计划只为浊音帧生成校正点，点里的 shift 等于目标音与原始音之差；⑥吸附目标是最近的音阶音，判断只在邻近音级之间取，不允许跨八度跳；⑦实际施加的偏移另存一份，受每秒半音的速率上限约束，理论偏移不受这个限制；⑧plan_correction 必须在分析之后调用，没分析过直接拒绝；⑨apply_segment 的区间必须有序且落在帧数范围内，与已提交区间重叠要拒绝，同一段重复提交也要拒绝；⑩committed_frames 返回已提交帧数，一条 take 可以分多次提交；⑪快照深拷贝 take、帧、音阶、曲线与已提交区间，恢复后全部还在，结构损坏整次拒绝且原状态不变。

两条硬约束：分析、计划、提交与快照要共用一把锁，别的线程读到的修正曲线必须是完整一版，不能一半新一半旧；速率上限、帧数上限与修正幅度都是硬约束，超限只能拒绝。轨迹口径另作约定：清音与气声帧没有稳定基频，必须保持原音高不吸附，不能按上一个浊音帧的目标硬拉；修正速率按半音每秒约束，跨八度误判时只允许就近吸附，不能整段跳八度；共振峰保持只移动基频包络，不得把整体频谱平移导致音色发闷，时长也不得随修正改变。快照是重启后的续算依据，恢复出来的已提交区间要与中断前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得改测试、跳过或按固定输入写死；速率限制与恢复续算自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: pitch_correction_planner
- typeName: PitchCorrectionPlanner
