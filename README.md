# batch50-py-game-b-02-p5

## 题面

角色跑动这周在真机上被挑出一串问题：循环跑动的接缝处每隔一轮就抖一下，看曲线是首尾对不上；手指和肩部的旋转在抽键之后出现细微抽搐，表现为插值出来的朝向偏离原动画；打包体积不降反升，同一根轨道压完关键帧反而比原来多；进程重启后压缩进度全丢，已经确认过的轨道又被重新抽了一遍，出包前的压缩环节只能靠人工盯着。范围是 gsb/batch50-py-game-b-02-p5 的 animation_curve_compressor.py，类 AnimationCurveCompressor，负责每个剪辑的轨道登记、误差有界抽键、循环闭合校验与按版本提交。

公开接口：AnimationCurveCompressor(*, max_tracks_per_clip=64, key_budget=256, error_bound=0.001, max_clips=32)；register_clip、clip_view、plan_tracks、compress_track、validate_loop、track_keys、report、commit、rollback、snapshot、restore、stats。拒绝一律抛 CurveError(code, detail)。

故障与边界：①登记时剪辑名去空白后不得为空，轨道数、关键帧预算、误差上界都要在范围内，重复登记报 CURVE_CLIP_EXISTS，参数非法报 CURVE_INVALID_REQUEST；②plan_tracks 按轨道名升序返回，每条带 kind、key_budget、error_bound，未知 kind 报 CURVE_UNKNOWN_KIND，重名或空名报 CURVE_INVALID_REQUEST，超过剪辑登记轨数报 CURVE_TRACK_BUDGET；③关键帧号必须严格递增，否则报 CURVE_FRAME_ORDER，值元组长度按 position 与 scale 三位、rotation 四位校验，不足两帧同样拒绝；④compress_track 默认容差取剪辑的误差上界，可以收紧不可放宽，超界报 CURVE_TOLERANCE_TOO_LOOSE，非正容差报 CURVE_INVALID_REQUEST；⑤能被相邻帧线性还原的中间帧剔除，保留帧按容差网格量化，每个分量都是容差的整数倍，报告带 input_count、output_count、dropped_keys、max_deviation、within_bound；⑥拐点帧必须保留，偏差超过容差的帧不得剔除，一帧未剔时 status 为 kept，剔除过则为 compressed；⑦commit 之前 track_keys 仍返回当前版本的关键帧，staged 结果只在 report 里可见；⑧commit 要求所有已 plan 的轨道都有结果，缺的报 CURVE_INCOMPLETE_PLAN，成功后版本加一、staged 清空，track_keys 换成新关键帧；⑨rollback 丢弃全部 staged，版本与关键帧保持原样；⑩validate_loop 只对循环剪辑有效，非循环报 CURVE_NOT_LOOPING，返回 closure_error、within_bound 与 seam_frame；⑪snapshot 深拷贝 clips 与 stats，restore 结构非法报 CURVE_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 clips、plans、compressions、commits、rollbacks、dropped_keys、refusals。

硬约束：同一剪辑的并发压缩必须在同一把锁里串行，结束后 staged 只有一份、各项计数不丢；未提交结果不得替换现行版本，重启后从已提交轨道续跑，不重抽已提交的轨道；旋转轨道剔除关键帧后必须重新归一化四元数并按球面插值复核偏差，不能按线性分量估算；循环片段首尾切线要保持连续，末帧被剔除后首尾差值仍须落在误差上界内；某条轨道压缩后关键帧数反而增加时保留原轨道，不得为凑统一预算写入更差的结果。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: animation_curve_compressor
- typeName: AnimationCurveCompressor
