# batch50-py-game-c-09

## 题面

小剧场换了无线手持麦以后，扩声每隔几分钟就啸叫一次，调音师把均衡器拉满也没压住，最后只能把总音量降下来，观众抱怨听不清；换了新话筒头以后，啸叫频点在两个相邻频点之间来回跳，陷波表一下子被占满，真正的新啸叫反而没有位置可用，演出中间根本来不及手动复位。抑制模块在 gsb/batch50-py-game-c-09 的 feedback_suppressor.py，类型 FeedbackSuppressor，负责从频谱里找持续窄带啸叫、分配陷波并把预算看住。

对外接口：FeedbackSuppressor(*, sample_rate=48000, detect_floor=0.6, notch_cap=8, hold_ms=500, ceiling_db=-6.0)；feed_spectrum(bins)；detect_feedback()；allocate_notch(freq_hz, depth_db=None)；release_notch(notch_id)；set_ceiling(ceiling_db)；set_sample_rate(rate)；set_hold_ms(ms)；advance_time(ms)；notch_table()；stats()；snapshot()；restore(state)。异常统一 FeedbackError(code, detail)，检测结果 FeedbackPeak(freq_hz, confidence, bin_index, confirmed)，陷波为 NotchFilter(notch_id, freq_hz, depth_db, bandwidth_hz, remaining_ms)。

要修的地方：一、频谱长度第一次喂入即固定，之后长度不符整帧拒绝；二、频点宽度等于采样率一半除以 bin 数，采样率变化后重建映射并丢弃旧帧；三、峰值取局部最大、不低于 detect_floor、同时不低于左右各两个邻点均值四倍的 bin，频率按 bin 序号乘频宽给出；四、同一 bin 连续三帧才算确认，置信度按已见帧数除以三递增，未确认的不许自动占用陷波；五、平坦频谱不得报出峰值；六、allocate_notch 自增编号，深度缺省时取当前 ceiling，编号、频率、剩余保持时间都要能在 notch_table 里读到，到 notch_cap 后拒绝新增并计数；七、release_notch 释放指定陷波，重复释放返回 False；八、ceiling 必须是负数且绝对值不超过 24，advance_time 只接受非负毫秒并返回本次释放的陷波数；九、notch_table 按频率升序返回，stats 汇总帧数、确认次数、分配、释放、拒绝、当前采样率与 ceiling。

十、同一啸叫在相邻频点抖动时只能共用一个陷波并向两侧展宽，不能不断新增把预算吃光；十一、陷波释放必须等啸叫连续消失超过保持时间，间歇性出现只重置保持计时、不释放；十二、多个陷波叠加后的总衰减要按频响曲线复核，不能简单按单个深度相加。

硬约束：识别与分配会被采集线程和界面线程同时触发，陷波表在任意时刻只能看到完整的一份，同一频点不许并发建出两个陷波，编号不许重复；快照要能整体取出并原样加载，恢复后陷波编号、剩余保持时间与计数都一致，结构不合法的快照整份拒绝且不动现场。陷波数量与总衰减是硬顶，超限只能拒绝，不能挤掉已有陷波。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不许改测试、不许跳过、不许按固定输入写死；并发分配与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-game-c-09
- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: feedback_suppressor
- typeName: FeedbackSuppressor
- file: feedback_suppressor.py
