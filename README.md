# batch50-py-game-c-08

## 题面

新采样器上线后，钢琴音色一踩踏板就串音，鼓组里同一个按键被连按两次时第二个音直接把第一个音硬切断，爆音很明显；复音数调到 32 以后又出现整体音量骤降，客服收到一堆和弦缺音的工单，混音师现场试听还发现低音区的长音会莫名消失。旧版偷声只看声部年龄，把优先级更高的铺底音偷掉了，主旋律反而断在半句上。发声分配这段在 gsb/batch50-py-game-c-08 的 sampler_voice_allocator.py，类型 VoiceAllocator，负责声部分配、偷声与释放。

对外接口：VoiceAllocator(*, polyphony=8)；note_on(note, *, sample_id="default", velocity=100, group=None, priority=None)；note_off(note)；set_polyphony(n)；set_priority(sample_id, priority)；set_sample_limit(sample_id, limit)；set_sustain(on)；steal(note)；panic()；active_voices()；group_voices(group)；voice_count()；snapshot()；restore(state)；stats()。异常统一 VoiceError(code, detail)，VoiceInfo 带 voice_id、note、sample_id、group、stage、priority。

要修的地方：一、音符只允许 0 到 127，力度只允许 1 到 127，越界整次拒绝且不占声部，声部编号从 1 单调递增，释放后不回收也不复用；二、达到复音上限时按优先级低者先偷，同优先级偷最旧的，偷声要计数；三、set_polyphony 传 0 或负数拒绝，调小上限要把多出来的声部按同样规则收掉；四、note_off 释放对应声部并返回释放条数，音符不在时返回 0 且不报错；五、steal(note) 主动收掉该音符的声部并返回声部编号，没有就返回 None；六、同一 group 内的音符互斥，组里已有声部时新音符进来后该组只能留一个活动声部，且新音符必须在其中；七、同一 sample_id 的活动实例数到 set_sample_limit 的上限后拒绝新音符并报错，已发声部不动；八、panic 收掉全部活动声部，清空组信息并计数；九、active_voices 按声部编号升序返回，group_voices 只看指定组，stats 汇总 note_ons、note_offs、steals、panics、active 与当前 polyphony，快照恢复后活动声部、下一个声部编号、优先级表与计数都要一致。

十、偷声挑中仍在释放尾音的声部时要快速淡出，不能硬切造成爆音；十一、延音踏板按下时 note_off 只标记待释放，不许立即回收声部；十二、同组互斥的新音符优先偷同组最旧的声部，同组没有可偷的才按全局优先级挑。

硬约束：note_on 会被多路 MIDI 线程同时调用，声部数永远不得超过当前复音上限，组互斥与偷声判定必须在同一把锁内完成，不能出现两个线程各偷一半，也不能让同一次按键分到两个声部；快照结构不合法时整份拒绝并保留现场，恢复后继续发声的声部编号不得与已有记录冲突，已经在响的音符不能换音高。复音上限与单采样实例数是硬顶，超限只许拒绝或按规则偷声，不许静默丢音。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不许改测试、不许跳过、不许按固定输入写死；并发 note_on 与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-game-c-08
- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: sampler_voice_allocator
- typeName: VoiceAllocator
- file: sampler_voice_allocator.py
