# batch50-py-game-c-03

## 题面

转码集群这周被一批竖拍素材拖住了：同一支片子在 iOS 上正着播、到了盒子端横躺着，还有一批左右反了；运营重新跑了一遍归一化，画面被转了两次，宽高也换错了位；带翻转的素材在流水线里直接被判为不支持，整批任务卡在待处理；有一支 3840×2161 的奇数高度素材旋转后被裁掉一条边，画面中心偏了半个身位；非方形像素的老素材归一化之后人脸被拉长，回滚之后元数据又和原文件对不上；素材库里同一条片子被转出两版，质检分不清哪版能直接上线。范围是 gsb/batch50-py-game-c-03 的 media_rotation_normalizer.py，类 MediaRotationNormalizer，负责读取显示矩阵与像素宽高比、折算滤镜链、登记归一化计划、执行与回滚，供转码集群和素材库共用。

公开接口：MediaRotationNormalizer(*, profile="mp4-h264", allow_downscale=False)；register(asset_id, *, width, height, rotation=0, flip_h=False, flip_v=False, sar="1:1")；inspect(asset_id)；plan_filters(asset_id)；normalize(asset_id)；apply(plan_id)；rollback(asset_id)；metadata_of(asset_id)；is_normalized(asset_id)；pending_plans()；discard_plan(plan_id)；snapshot、restore、stats。拒绝统一抛 MediaError(code, detail)。

故障与边界：①asset_id 去空白后不得为空，width、height 取正整数，rotation 只收 0、90、180、270，sar 形如 分子:分母 且都为正整数，非法抛 MEDIA_ASSET_INVALID，重复 asset_id 抛 MEDIA_ASSET_EXISTS；②inspect 返回 asset_id、rotation、flip_h、flip_v、width、height、sar、output_width、output_height、normalized、revision，sar 以分子分母元组记录，90 与 270 输出宽高互换，180 不变；③纯旋转的滤镜链分别是空、transpose=1、rotate=180、transpose=2，单独水平翻转是 hflip；④带翻转又带旋转的素材要折算成等价的顺时针角度继续处理，不能拒绝也不能丢掉翻转信息；⑤像素宽高比不为 1 时先旋转再缩放，顺序颠倒会把画面拉长；⑥normalize 生成 plan-0001 递增的计划并返回 status 为 planned，同一素材已有待执行计划时返回原计划 id，pending_plans 返回按序号升序的元组，plans 只加一；⑦已归一化的素材再 normalize 返回 status 为 skipped、filters 为空，skipped 加一且 revision 不变；⑧apply 只接受待执行计划，未知或已消费的计划抛 MEDIA_UNKNOWN_PLAN，成功后 normalized 置真、revision 加一、写入 after 元数据并计 applied；⑨metadata_of 返回 {asset_id, before, after, normalized, revision} 的深拷贝，before 与 after 各含 rotation、flip_h、flip_v、width、height、sar，after 的 rotation 固定为 0、宽高取输出尺寸，未归一化时 after 为 None；⑩rollback 只在已归一化时可用，恢复 before 元数据、清空 after、revision 再加一，未归一化时抛 MEDIA_NOT_NORMALIZED；⑪discard_plan 丢弃待执行计划并返回布尔值，未知计划返回 False，计入 discarded；⑫snapshot 返回 {version, assets, plans, sequence, stats} 的深拷贝，restore 校验版本、字段类型与统计项齐全，结构非法抛 MEDIA_SNAPSHOT_INVALID 且原状态不变，未知素材在 inspect、plan_filters、normalize、metadata_of 上统一抛 MEDIA_UNKNOWN_ASSET；stats 至少含 registered、plans、skipped、applied、rollbacks、discarded。

硬约束：register、normalize、apply、rollback、discard_plan 必须在同一把锁内完成，并发登记与执行时同一素材只能有一份待执行计划、revision 单调递增、计划序号不重号；快照恢复后素材元数据、待执行计划、序号与全部计数都要在，且不得与调用方共享可变结构；同一素材重复归一化必须幂等，奇数尺寸旋转后按偶数对齐裁剪时画面中心不得偏移。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: media_rotation_normalizer
- typeName: MediaRotationNormalizer
