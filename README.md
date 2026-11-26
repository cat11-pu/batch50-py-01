# batch50-py-game-c-07

## 题面

综艺棚四个机位同期录制，后期对轨时发现 B 机位整段比 A 晚了两秒多，C 机位开头对得上、到第四十分钟又慢慢跑掉；低置信度的机位被程序直接对齐，成片里口型和鼓点对不上；更糟的是同一项目换版本重算时，人工调好位置的机位又被挪走，剪辑师只能重新拖一遍时间线，一集要多花两天。对轨程序在 gsb/batch50-py-game-c-07 的 multicam_sync_aligner.py，类型 MulticamSyncAligner，负责按音频包络指纹估偏移、把多个机位对到同一时间线并给出漂移报告。

对外接口：MulticamSyncAligner(*, window_ms=10, max_lag_ms=500, segment_ms=1000, max_tracks=16)；ingest_track(track_id, samples, sample_rate=48000)；estimate_offset(track_id, reference_id)；align(reference_id)；drift_report(track_id, reference_id=None)；commit(project_version)；lock_track(track_id)；track_info(track_id)；fingerprint_count(track_id)；set_max_tracks(n)；track_stats()；snapshot()；restore(state)。异常统一 SyncError(code, detail)，估偏移返回 OffsetEstimate(track_id, offset_ms, confidence, ambiguous)，漂移段为 DriftSegment(start_ms, end_ms, drift_ppm)。

要修的地方：一、每条轨道按 window_ms 切窗求 RMS 得指纹，最后一窗不足整窗就丢掉，条数要能被 fingerprint_count 读出；二、空样本、不足一个整窗、非正采样率、重复 track_id 的轨道整条拒绝，原有轨道数据不受影响；三、偏移按指纹互相关峰值所在的窗口差乘 window_ms 得到，正值表示该轨比基准晚、需要提前同样毫秒；四、未入库的轨道与未知的基准轨分别报错，不许拿空结果糊过去，置信度归一化到 0 到 1，干净素材不能带 ambiguous 标记；五、置信度不达标的轨道要留人工确认标记，不许直接当基准；六、align 以基准轨为 0，返回覆盖全部轨道的整数偏移，缺一条都不算完成；七、drift_report 按 segment_ms 切段，段边界从 0 起连续，纯整体平移的素材每段漂移都应为 0，单位 ppm；八、commit 记下项目版本号并冻结当次对齐结果，再次 align 不得重算；九、轨道数到 max_tracks 上限后拒绝新增，已入库轨道照常可用，track_info 给出采样率、指纹窗数与是否锁定，track_stats 汇总 tracks、ingests、estimates、commits、version。

十、两轨内容高度相似且带固定延迟时，互相关峰值可能落在倍周期上，必须用次峰校验排除整拍偏移，不能直接采信最高峰；十一、长时漂移按分段线性补偿时，段边界不得产生采样跳变；十二、已锁定的轨道在新增机位重算时偏移保持不变，只允许新轨道向基准靠拢。

硬约束：估偏移与 align 会被多个调度线程同时调用，读到的指纹与偏移表必须是完整的一份，不允许一半新一半旧；快照要深拷贝，恢复后指纹、偏移、锁定标记、项目版本与计数都在，结构不合法的快照整份拒绝且现有数据不动。轨道数上限是硬顶。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不许改测试、不许跳过、不许按固定输入写死；并发估偏移与恢复后重算自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-game-c-07
- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: multicam_sync_aligner
- typeName: MulticamSyncAligner
- file: multicam_sync_aligner.py
