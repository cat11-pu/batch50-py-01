# batch50-py-game-c-01

## 题面

混音服务这周在攻城战里连续翻车：四十多个音效同时进场时 BGM 被莫名掐断，技能音和脚步声互相盖掉；同一路音源同时占了两个声部，播放时叠出明显回声；被高优先级抢走的音效本该等资源空出来再补播，结果一整场都没再响过，运营翻日志也找不到它去了哪里；运维把声部上限从 24 调到 16 之后，正在淡出的声部没有被算进去，帧内计数对不上，包体在低端机上直接爆音。范围是 gsb/batch50-py-game-c-01 的 voice_stealing_allocator.py，类 VoiceStealingAllocator，按帧维护声部池、抢占记录与虚拟队列，供混音线程、战斗回放和排查脚本共用。

公开接口：VoiceStealingAllocator(*, capacity=24, fade_frames=2, virtual_timeout=120)；request_voice(source_id, *, priority=0, distance=0.0, frame=None)；touch(source_id, *, frame=None)；release(voice_id)；preempt(voice_id, *, reason="manual")；tick(*, frames=1)；virtual_queue()；voice_of(source_id)；voices(*, state=None)；set_capacity(capacity)；free_slots()；snapshot、restore、stats。所有拒绝统一抛 VoiceError(code, detail)，调用方按 code 分支处理。

故障与边界：①source_id 去两端空白后不得为空，priority 只收 0 到 15 的整数，distance 不得为负，任何一项非法都抛 AUDIO_VOICE_INVALID 且本次请求不记入统计；②同一音源已经占着声部时不得再开第二路，重复请求返回原声部、只刷新最近使用帧，优先级和距离保持首次请求的值，duplicates 加一；③池内有空位就立即分配，voice_id 按 voice-0001 递增，起播帧与最近使用帧取当前帧，voices 返回按优先级升序、音源名升序排列的元组，state 可筛 live 与 fading；④容量满时只有比当前最弱活声部更强的请求才准入，优先级高为强、同优先级距离近为强，否则返回 None 并计 refused，被拒的请求不得进入虚拟队列；⑤自动抢占与显式 preempt 都在同一个临界区里完成让位，被抢声部立刻停止并进入虚拟队列记录为 stolen 或调用方给的 reason，任何时刻 live 加 fading 都不能超过 capacity；⑥release 把声部置为 fading 继续占槽，tick 每帧递减，减到零才真正释放，对淡出中的声部重复 release 抛 AUDIO_UNKNOWN_VOICE；⑦preempt 对未知 voice_id 同样抛 AUDIO_UNKNOWN_VOICE，队列条目按 virtual-0001 递增编号并保留原始请求帧；⑧tick 有空位时按优先级降序、距离升序、请求帧升序恢复虚拟队列，一次恢复数量不超过当时空位数，返回本次恢复的 voice_id 与推进后的帧号；⑨虚拟条目在队列里等待超过 virtual_timeout 帧就作废，作废后不再恢复，但 expired 计数要保留下来供排查；⑩同优先级抢位时受害者按最久未使用挑选，而不是按谁先请求；⑪set_capacity 小于 1 抛 AUDIO_VOICE_INVALID，扩容立即生效，缩容从最弱活声部开始移入虚拟队列并计 evictions；⑫snapshot 返回 {version, capacity, frame, voices, virtual, stats} 的深拷贝，restore 校验版本、字段类型与统计项齐全，结构非法抛 AUDIO_VOICE_SNAPSHOT_INVALID 且原状态不变，恢复后帧号接着快照里的值走。

硬约束：request_voice、release、preempt、tick、set_capacity 必须在同一把锁内完成，并发压测下同一音源不得占两个槽、live 加 fading 不得超容量、各项计数与最终声部集合必须自洽；快照恢复后帧号、淡出剩余帧、虚拟队列顺序与全部计数都要在，且不得与调用方共享可变结构。stats 至少含 requests、duplicates、refused、steals、evictions、recovered、expired。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: voice_stealing_allocator
- typeName: VoiceStealingAllocator
