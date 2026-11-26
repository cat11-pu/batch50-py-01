# batch50-py-game-c-02-p5

## 题面

棚里给一首已经混好的曲子补录人声，歌手跟着伴奏唱完，回放时新录的人声比伴奏晚了将近一个节拍，越往后拖得越明显；补录段落接回去时留了硬切口，和声被切断，切几次之后同一个小节里两个版本一起响。现场用 loopback 量过监测链路，延迟数字每台机器都不一样，换一次声卡就得重新量，量出来的值还忽大忽小，录音助理手工挪过两次也没对齐，换到 96k 采样率时偏差又换了个方向。范围是 gsb/batch50-py-game-c-02-p5 的 overdub_latency_aligner.py，类 OverdubAligner 负责往返延迟测量、按整数采样对齐新录片段、给出 punch 区间并原子提交替换。

公开接口：OverdubAligner(*, max_latency=48000, drift_limit=500, max_tracks=16)；add_track(track_id, sample_rate, *, max_latency=None)；calibrate(track_id, measurements)；set_latency(track_id, latency_samples)；place_take(track_id, take_id, start_sample, length)；punch_range(take_id, start_sample, end_sample)；align_take(take_id)；take_of(take_id)；commit(take_id)；discard_take(take_id)；committed_spans(track_id)；drift_estimate(track_id)；stats、snapshot、restore。拒绝操作抛 OverdubError(code, detail)，错误码统一用 OVERDUB_ 前缀：INVALID_REQUEST、DUPLICATE_TRACK、TRACK_LIMIT、DRIFT_EXCEEDED、LATENCY_TOO_LARGE、DUPLICATE_TAKE、TAKE_NOT_ALIGNED、COMMIT_CONFLICT、SNAPSHOT_INVALID；stats 返回 tracks、takes、committed、replaced、calibrations 五个计数。

故障与边界：①轨道采样率必须为正，新轨道延迟从零起，重复 track_id 拒绝，轨道总数受 max_tracks 硬顶；②校准至少要给一个测量值，生效延迟取测量中位数并由 calibrate 返回，且不得超过该轨道的延迟上限；③漂移估计取最大值与最小值之差的一半，超过 drift_limit 要报错要求重新校准，这次校准不得改动已有延迟；④set_latency 只收 0 到上限之间的整数，负数与超上限分别拒绝；⑤place_take 起点不得为负、长度必须为正，take_id 重复拒绝；⑥对齐只做整数采样，对齐起点等于放置起点减当前延迟，结果要能从 take_of 读回；⑦punch 区间必须起止有序并落在 take 区间内，提交前必须有合法 punch；⑧提交按 punch 区间替换同轨道上重叠的旧 take，旧 take 状态置为 replaced、新 take 置为 committed，不做物理删除，返回的 replaced 标志与合并后的区间要对得上；⑨相邻区间提交后合并成一段，committed_spans 按起点升序；⑩未提交 take 可以丢弃，已提交的 take 丢弃要拒绝，同一 take 重复提交也要拒绝；⑪快照深拷贝轨道、take、延迟、漂移与已提交区间，恢复后全部还在，结构损坏整次拒绝且原状态不变。

两条硬约束：提交、对齐、快照要走同一把锁，同区间的替换、区间表重写与状态标记必须一步完成，读方只能看到替换前或替换后的完整区间表。迟到与冲突的口径另定：延迟校准值改过之后，已提交片段不得追溯移动，只有未提交的 take 使用新值；punch 区间跨越已有片段边界时，接缝淡入淡出长度取两侧较短者且不得重叠；重录 take 提交失败时旧 take 必须保持可用，绝不能出现两版都不生效。快照是重启后的唯一依据，恢复出来的延迟、漂移、状态与区间表要与中断前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得改测试、跳过或按固定输入写死；延迟变更与提交冲突自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: overdub_latency_aligner
- typeName: OverdubAligner
