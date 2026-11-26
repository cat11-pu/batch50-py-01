# batch50-py-game-c-03-p5

## 题面

编曲同事把一段 demo 交给配乐组之后，同一份 MIDI 在宿主里播放时鼓点越来越赶，副歌前的变速段整块前移，量化过的军鼓从第九小节起跑到小节线外面；启用三连音网格之后摇摆值又被叠了一次，听起来像两套网格在打架，导出音频跟视频对帧时整段偏了半拍，配乐组已经临时关掉量化交付，等修好再重开。范围是 gsb/batch50-py-game-c-03-p5 的 tempo_map_quantizer.py，类 TempoMapQuantizer 维护变速锚点与拍号映射，负责拍位与采样时间互换、按网格吸附音符事件。初始映射是 120 拍、4/4 拍、480 个 tick 一拍、48k 采样率。

公开接口：TempoMapQuantizer(*, ppq=480, sample_rate=48000, max_anchors=256)；add_tempo(tick, bpm)；add_meter(tick, numerator, denominator)；remove_tempo(tick)；tick_to_sample(tick)；sample_to_tick(sample)；quantize(tick, *, grid="1/16", triplet=False, swing=0.0)；grid_at(tick, grid="1/16", *, triplet=False)；anchors()；meter_at(tick)；bar_line(tick)；stats、snapshot、restore。add_tempo 与 add_meter 返回写入的锚点，grid_at 返回该网格的 tick 数。拒绝操作抛 TempoMapError(code, detail)，错误码统一用 TEMPO_ 前缀：INVALID_REQUEST、INVALID_BPM、ANCHOR_LIMIT、INVALID_METER、INVALID_METER_POSITION、GRID_UNSUPPORTED、UNKNOWN_ANCHOR、SNAPSHOT_INVALID；stats 返回 tempos、meters、quantized、removed、refuses 五个计数，tempos 与 meters 把默认锚点也算在内。

故障与边界：①bpm 必须为正且不超过 400，tick 不得为负，越界分别拒绝；②同一 tick 重复变速只保留最后一次，anchors 始终按 tick 升序；③锚点数量受 max_anchors 硬顶，超限拒绝，不许顶掉已有锚点；④拍号分子取 1 到 16、分母限定 2、4、8、16、32，非法拍号拒绝；⑤拍号变化必须落在当前拍号的小节线上，落不到小节线拒绝；⑥tick_to_sample 按分段线性换算，每段用本段 bpm，段边界接着上段末尾累加，不能出现整段漂移；⑦sample_to_tick 是它的反向换算，负数采样直接拒绝；⑧量化吸附到当前拍号段内最近的网格点，网格原点取该段小节线；⑨网格只认 1/4、1/8、1/16、1/32，其它写法拒绝，三连音网格是普通网格的三分之二；⑩量化正好落在两个网格点中间时取靠前的一个；⑪删除变速锚点要返回被删的那一条，位置 0 的默认锚点不允许删除，不存在的 tick 报未知锚点；⑫快照深拷贝锚点、拍号与计数，恢复后 anchors、meter_at、换算结果与统计都在，结构损坏整次拒绝且原状态不变。

两条硬约束：编辑锚点与查询换算要共用一把锁，查询读到的映射必须是某次编辑完成后的完整锚点表，不能读到只加了一半的区间；锚点数量、拍号数量与网格倍率都是硬上限，拍号切到 6/8 之后小节线也不能按 4/4 算。跨段口径另作约定：量化不许把音符吸附到另一个拍号段的小节线，跨过段边界时按所在段自己的网格算；三连音与摇摆同时开启时以显式网格为准，不再叠加第二次偏移；删除中间某个变速锚点后，其后所有事件的采样时间要按新表整体重算，不许沿用旧缓存。快照是重启后的续算依据，恢复出来的锚点表要与中断前一致。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得改测试、跳过或按固定输入写死；并发编辑与恢复续算自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: tempo_map_quantizer
- typeName: TempoMapQuantizer
