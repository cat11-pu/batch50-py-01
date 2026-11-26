# batch50-py-game-c-04

## 题面

音频库这周被判重系统坑了两次：同一首广告歌被不同剪辑重复入库，查重时命中数翻倍，运营以为又抓到一起盗用；另外两段只是伴奏相似的曲子被直接判成重复下架，作者拿着工单来投诉；索引跑满之后新歌进不来，淘汰掉的老歌第二天又被查重命中，日志里却找不到它的记录；还有一条复核单在库里挂着，条目被淘汰之后就再也打不开。范围是 gsb/batch50-py-game-c-04 的 audio_fingerprint_index.py，类 AudioFingerprintIndex，负责指纹入库、近似查重、容量淘汰与复核队列，供版权审核与素材检索共用。

公开接口：AudioFingerprintIndex(*, capacity=64, hit_threshold=4)；index(clip_id, *, hashes, meta=None)；query(hashes)；remove(clip_id)；capacity()；set_capacity(capacity)；evict()；review_queue()；resolve_review(review_id, *, decision)；entry_of(clip_id)；entries()；size()；snapshot、restore、stats。拒绝统一抛 FingerprintError(code, detail)。

故障与边界：①clip_id 去空白后不得为空，hashes 必须是非空的整数序列，meta 只收字符串键值，非法抛 AUDIO_FP_INVALID；②入库指纹先去重再升序排列，重复指纹只算一次，条目记录 clip_id、hashes、indexed_seq、last_hit_seq 与排序后的 meta 元组，序号从 1 开始递增；③同一 clip_id 重复入库只替换指纹与元数据，indexed_seq 保持不变、last_hit_seq 刷新，计 reindexed，索引条目不增加；④query 的 hits 取查询指纹集合与条目指纹集合的交集大小，similarity 等于 hits 除以两侧较短长度并保留三位小数；⑤hits 大于阈值判定 duplicate，等于阈值转入复核队列而不是直接判重，小于阈值给 below，没有任何交集的条目不返回；⑥命中数大于零的条目都要刷新 last_hit_seq，结果按 hits 降序、clip_id 升序返回元组；⑦复核记录按 review-0001 递增编号，保存 clip_id、命中数、相似度与指纹摘要，resolve_review 只接受 duplicate 与 distinct 两种结论，未知单号抛 AUDIO_FP_UNKNOWN_REVIEW；⑧被淘汰条目的指纹残片不得再参与后续查询，但复核队列里的记录保留对原条目的引用，单号仍可查；⑨容量按条目数计算，set_capacity 收正整数否则抛 AUDIO_FP_INVALID，缩容立即按最近命中时间从旧到新淘汰并计 evicted；⑩索引满时入库先淘汰最久未被命中的条目再写入，evict 只在满员时动作、成功返回 clip_id，未满返回 None；⑪remove 对不存在的条目返回 False 且不计数，存在时删除并计 removed；⑫snapshot 返回 {version, capacity, entries, reviews, sequence, stats} 的深拷贝，restore 校验版本、字段类型与统计项齐全，结构非法抛 AUDIO_FP_SNAPSHOT_INVALID 且原状态不变；stats 至少含 indexed、reindexed、removed、evicted、queries、duplicates、reviews、resolved。

硬约束：index、query、remove、set_capacity、evict、resolve_review 必须在同一把锁内完成，并发入库时条目总数不得越过容量、序号不得重号、命中刷新与淘汰顺序必须自洽；快照恢复后条目指纹、最近命中序号、复核记录、容量与全部计数都要在，且不得与调用方共享可变结构；同一段音频重复入库不得产生双倍命中。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: audio_fingerprint_index
- typeName: AudioFingerprintIndex
