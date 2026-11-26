# batch50-py-game-c-02

## 题面

新版本播放器上线后音轨切换的客诉堆了一摞：从国语切到日语时两路声音同时出来，持续半秒才收掉一路；片头按设备语言自动选轨，日语音轨缺失的机器上整段没有声音，字幕也被一起关掉；预加载失败之后播放器停在一条不存在的目标轨上，进度条照走但没人声；有一批片子切点落在非关键帧，画面接缝处咔哒一声；用户连按两次切换，第二次把第一次的预加载挤掉了，最后两路都没生效。范围是 gsb/batch50-py-game-c-02 的 audio_track_selector.py，类 AudioTrackSelector，负责音轨登记、按设备能力与偏好选轨、预加载窗口、关键帧切换与语言回退，供播放器内核和机顶盒固件共用。

公开接口：AudioTrackSelector(*, system_language="zh", default_language="und", max_preloaded=2, device_codecs=("aac","opus"), max_channels=8)；add_track(track_id, *, language, keyframes=(0,), codec="aac", channels=2, bitrate=128000)；set_device(*, codecs=None, max_channels=None)；set_preference(languages)；available(*, language=None)；preload(language)；switch_to(language, *, position=0)；advance_to(position)；current()；active_tracks()；fallback_chain()；abort_preload(language=None)；abort_switch()；snapshot、restore、stats。所有拒绝统一抛 TrackError(code, detail)。

故障与边界：①track_id 与 language 去空白后不得为空，keyframes 必须是升序且互不重复的非负整数，bitrate 与 channels 取正整数，非法抛 AUDIO_TRACK_INVALID，重复 track_id 抛 AUDIO_TRACK_EXISTS；②set_device 的 codecs 至少一项、max_channels 为正整数，否则 AUDIO_DEVICE_INVALID，available 只列设备能解的轨并按 language、track_id 升序返回元组；③set_preference 去空白、转小写、保序去重，空列表或非字符串抛 AUDIO_PREFERENCE_INVALID；④preload 命中可播轨返回 ready 并记下 track_id，语言没有任何轨返回 missing、reason 为 no_track，设备解不了返回 unsupported、reason 为 device，两次失败都计 preload_failures，成功计 preloads；⑤预加载窗口受 max_preloaded 限制，超出时淘汰最早预加载的那条并计 preload_evictions；abort_preload 返回本次清掉的条数，重复调用返回 0，aborts 只在真正清掉时加一；⑥switch_to 目标语言没有 ready 的预加载就抛 AUDIO_PRELOAD_REQUIRED；目标就是当前轨时直接返回 unchanged，不动计数也不需要预加载；⑦切换点必须落在目标轨的关键帧上，position 正好是关键帧才立即 applied，落在两个关键帧之间要排队等下一个同步点，不能提前切；⑧切换生效后 current 换成目标轨、预加载记录被消费、switches 加一，active_tracks 返回元组且任何时候长度不超过 1，不允许双轨同时出声；⑨请求的语言缺失时按用户偏好、系统语言、默认语言逐级回退，回退成功记 fallbacks，全部缺失时保持静音但字幕照常显示；⑩fallback_chain 返回去重后的语言尝试顺序，不受 available 结果影响；⑪snapshot 返回 {version, tracks, preferences, device, current, preloaded, queued, position, stats} 的深拷贝，restore 校验版本、字段类型与统计项齐全，结构非法抛 AUDIO_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 switches、queued、preloads、preload_failures、preload_evictions、aborts、fallbacks。

硬约束：add_track、set_device、set_preference、preload、switch_to 必须在同一把锁内完成，并发切换时同一时刻只能有一条轨出声，switches 计数与实际生效次数一致，预加载窗口不得因并发超出上限；快照恢复后音轨表、偏好、设备能力、当前轨、预加载窗口、排队中的切换与位置都要在，且不得与调用方共享可变结构。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: audio_track_selector
- typeName: AudioTrackSelector
