# batch50-py-game-b-01

## 题面

夜班值守接到美术组告警：雪山关卡的冰晶特效在密集视角下整体发黑，同一像素叠上十几层半透明片元后画面忽明忽暗，切分辨率时还会闪一帧全黑；更糟的是轻量级设备上帧时间直接翻倍，掉帧从山谷一路蔓延到主城。渲染组排查后把问题归到半透明暂存：片元列表没有容量预算，溢出时随机丢弃最远或最近的层，帧末尾的合成顺序取决于提交先后，同一深度的片元谁先谁后完全看线程调度；断线重连后已经入队但尚未合成的片元全部消失，画面要等下一帧才恢复。同一套代码还要同时跑在手机与 PC 上，容量配置只在启动时读一次，运行中不允许整段重建。范围是 gsb/batch50-py-game-b-01 的 oit_fragment_budget.py，类 OitFragmentBudget，负责每像素片元暂存、深度排序、溢出降级与帧末合成，并要能把未完成的一帧原样带到下一次进程启动。

公开接口：OitFragmentBudget(*, capacity=8, merge_mode="average")；begin_frame(frame_id, *, width, height)；push_fragment(*, x, y, depth, color, alpha=1.0, seq=None)；resolve_pixel(*, x, y, background=(0, 0, 0))；pending_count(x=None, y=None)；frame_info()；set_capacity(capacity)；overflow_stats()；reset()；snapshot() 与 restore(state)；stats()。拒绝一律抛 OitError(code, detail)。

故障与边界：①未开始帧就入队抛 OIT_FRAME_NOT_STARTED；②frame_id 重复或回退抛 OIT_FRAME_ORDER；③帧内仍有未合成片元时再次 begin_frame 抛 OIT_FRAME_PENDING；④坐标越界或非整数抛 OIT_INVALID_PIXEL，depth 为负、超过 24 位或非整数、color 不足 3 通道或通道超出 0-255、alpha 不在 (0,1] 抛 OIT_INVALID_FRAGMENT；⑤seq 由调用方给定时必须帧内唯一，重复抛 OIT_SEQ_DUPLICATE，未给时按 0 起自增，调用方给的序号也要参与后续去重；⑥同像素片元按 depth 升序（近在前），depth 完全相同的片元不做合并，按提交序号决定先后；⑦resolve_pixel 返回 fragments（按 depth 升序的元组，每项含 depth、seq、color、alpha、merged）、color、merged、dropped；合成由远及近做 alpha 混合，通道四舍五入取整，resolve 后该像素清空，再次查询只返回背景色；⑧超出容量时保留最近 capacity-1 条真实片元，最后 1 槽放被丢弃片元按 alpha 加权补偿成的平均色片元，drop 模式则直接丢弃最远片元、不设补偿槽；⑨像素首次溢出计一次 pixels_overflowed，dropped 与 merged 逐片元累计，overflow_stats 返回 pixels、dropped、merged 三个计数；⑩帧内有未合成片元时 set_capacity 抛 OIT_CAPACITY_LOCKED，容量不在 2-32 抛 OIT_INVALID_CAPACITY；⑪快照结构为 version/capacity/merge_mode/frame/stats，frame 下 pixels 是像素列表，stats 计数不得为负，恢复非法结构抛 OIT_SNAPSHOT_INVALID 且现场不变；⑫reset 清空帧、待合成片元与全部计数，frame_info 返回当前帧号、尺寸与各像素待合成数量。

硬约束：同一像素的入队与合成必须在同一把可重入锁内完成，并发入队不得丢失或重复 seq，也不得让两个线程各自合成出不同结果；快照必须深拷贝尚未合成的片元列表，恢复后继续 resolve 的结果必须与不中断时逐像素一致，包括溢出补偿后的槽位顺序。stats 返回 frames、fragments、resolved、dropped、merged、pixels_overflowed，其中 frames 为已开始帧数、resolved 为已合成片元数。

验收：python3 -m pytest -q tests 必须 15 条全过；不得改测试、跳过、按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: oit_fragment_budget
- typeName: OitFragmentBudget
