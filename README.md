# batch50-py-game-c-10

## 题面

直播转码集群上，切到某个 GOP 中间时画面出现大片绿块，播放器一直等到下一个关键帧才恢复，回看用户以为是片源坏了；另一路更怪，长期参考帧被替换后旧帧还在被引用，输出顺序直接错乱；还有一路重启后参考列表全空，整段画面糊成一片，运维只能整路重启，观众端先黑屏再重连。参考帧管理在 gsb/batch50-py-game-c-10 的 dpb_reference_manager.py，类型 DpbReferenceManager，负责槽位分配、参考标记、滑窗释放与清空。

对外接口：DpbReferenceManager(*, capacity=16, max_long_term=2)；allocate(frame_num, pic_num)；mark_reference(pic_num, *, long_term=False)；sliding_window()；clear_refs()；get_ref(pic_num)；flush()；mark_output_done(pic_num)；mark_gap(frame_num)；gap_pending()；set_max_long_term(n)；slot_table()；stats()；snapshot()；restore(state)。异常统一 DpbError(code, detail)，槽位视图 SlotView 带 slot、frame_num、pic_num、is_reference、long_term、long_term_index、output_done、generation。

要修的地方：一、分配永远取编号最小的空闲槽，槽位编号从 0 起，代际号每次分配加一，方便排查错位；二、同一 pic_num 不允许重复占用，重复分配要报错；三、槽位全被占满时分配失败，不许悄悄挤掉别的帧，也不许覆盖仍被参考的旧帧；四、mark_reference 给指定帧打参考标记并返回槽位号，短期参考的 long_term_index 记为 -1，标记不存在的帧要报错；五、长期参考按最小可用索引分配，数量到 max_long_term 后拒绝新增；六、sliding_window 释放最旧的短期参考帧并返回其 pic_num 列表，长期参考不在释放范围内；七、get_ref 只认参考帧，长期参考要能带出索引，clear_refs 一次性清掉全部参考标记并返回条数，槽位本身不释放；八、mark_output_done 记录帧已输出，flush 只回收已输出且未再被参考的槽位并返回条数，mark_gap 记录参考帧缺口次数，gap_pending 在缺口未清前为真；九、slot_table 按槽位升序，stats 汇总分配、回收、参考数、长期参考数、缺口数与容量。

十、参考帧缺失导致后续帧解不出来时只能标记缺口并等 IDR，绝不能拿非参考帧顶替；十一、长期参考被取消后它的槽位不得立刻复用，必须先等该帧输出完成；十二、同一帧被重复标记为参考时按幂等处理，不得重复占用长期索引。

硬约束：取参考与标记会被解码线程和输出线程同时调用，任一时刻 get_ref 与 slot_table 看到的必须是同一份完整状态，不允许标记写了一半就被读到；快照要能整体取出并原样加载，恢复后槽位、参考标记、长期索引、缺口与计数都一致，重启后从快照继续解码，结构不合法的快照整份拒绝且不动现场。槽位总数与长期参考数是硬顶。

验收：`python3 -m pytest -q tests` 的 15 条必须全过，不许改测试、不许跳过、不许按固定输入写死；并发取参考与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-game-c-10
- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: dpb_reference_manager
- typeName: DpbReferenceManager
- file: dpb_reference_manager.py
