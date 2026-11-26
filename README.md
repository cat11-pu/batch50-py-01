# batch50-py-game-b-07

## 题面

动作组把动捕采样导进引擎后撞上三件事：导出文件里关键帧密到把内存顶满，压掉一半后角色落地时脚会轻微滑一下，再压狠一点脚步音效又整体提前两帧。范围是 gsb/batch50-py-game-b-07 的 curve_keyframe_reducer.py，类 CurveKeyframeReducer，负责把高密度采样曲线按误差容限抽稀成稀疏关键帧、保留必须留下的锚点、按原采样率重建并给出误差统计；这些入口目前在代码里没有任何行为，一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：CurveKeyframeReducer(*, tolerance=0.01)；load(curve_id, samples, *, events=None, sample_rate=60)、set_tolerance(tolerance)、compress()、reconstruct()、forced_keys()、error_stats()、serialize_curve()、deserialize(blob)、snapshot()、restore(state)、stats()。拒绝一律抛 CurveReducerError(code, detail)。

故障与边界：①load 要求 samples 至少有 4 个数值，sample_rate 为正整数，events 去重升序且每个下标落在采样范围内，curve_id 去空白后非空，任一项不合规报 CURVE_INVALID_INPUT 且不改动已加载的曲线；②容差必须是有限正数，0、负数、NaN、Inf 报 CURVE_INVALID_TOLERANCE；容差一改，上一轮压缩结果立即作废，重建、误差统计与序列化都要先重新压缩，否则报 CURVE_NOT_COMPRESSED；③强制保留点包括首帧、末帧、第一个最大值、第一个最小值与全部事件锚点；事件锚点前后各保留一个关键帧，即使该区间本来可以直线插值；采样里的 NaN 原样保留并标记为不可插值，不参与极值判断，也不允许被抽掉；④compress 返回升序去重的下标列表，首帧与末帧必须在里面，同一输入重复压缩返回同一份下标，两个实例跑同一输入的结果逐项一致；⑤抽稀按误差容限进行，所有可插值采样点的重建值与原值之差都不得超过当前容差，不许为了少留关键帧而放宽容差；容差收紧后关键帧数量不得减少，完全线性的曲线只保留首尾两帧；⑥reconstruct 按原采样数返回，关键帧处取原值，相邻关键帧之间按线性插值补齐，长度必须等于采样数；⑦error_stats 返回 samples、keys、tolerance、max_error、mean_error、violations 六个字段，violations 统计超出容差的采样点数，正常压缩后必须为 0，mean_error 不得大于 max_error；⑧forced_keys 只依赖已加载的曲线，返回升序去重的下标元组；未 load 时 compress、reconstruct、forced_keys、error_stats、serialize_curve 一律报 CURVE_NOT_LOADED；⑨serialize_curve 输出单行文本并以 CURVE1| 起头，依次携带曲线名、采样率、容差、事件下标、关键帧下标与全部采样值；同一个 reducer 连续两次输出、两个实例对同一输入都必须逐字节一致；⑩deserialize 校验版本前缀与字段集合，版本不符、字段缺失、字段重复、数值越界报 CURVE_SERIALIZE_INVALID 且不改动当前曲线，成功后返回与 load 相同的元信息，并且可以直接重建、按同一容差再压缩得到同一份关键帧；⑪snapshot 固定为 version、curve_id、sample_rate、tolerance、samples、events、keys、counters 八个键，整体是深拷贝，restore 校验结构，缺键、版本不符或类型不对报 CURVE_SNAPSHOT_INVALID 且原状态不被改动；⑫恢复后容差、事件、关键帧与压缩计数都要继续可用，重启不必重新抽稀也能直接重建。

硬约束：误差预算是硬约束，任何一轮压缩都不许出现超出容差的采样点，也不许用提高容差的办法让统计变好看；同一输入两次压缩与序列化必须逐字节一致，关键帧顺序与插值结果不得依赖字典或集合的遍历顺序；快照与恢复要在同一把锁内完成，恢复失败时曲线、容差、关键帧与计数都不留半截改动；重新 load 会清空上一轮压缩结果，但累计压缩次数保留。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；题面点到的每一项都要落到代码行为上；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: curve_keyframe_reducer
- typeName: CurveKeyframeReducer
