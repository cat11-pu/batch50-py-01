# batch50-py-game-b-10

## 题面

植被系统换到新驱动后，验收机上草地出了几种怪相：远处的灌木每隔几帧猛地跳一下位置，凑近看又没有规律；风向一转，整片草先僵住半秒再瞬间甩到新方向；把更新预算调小后，近处草不摆，远处的树照摆不误；重进关卡时风又回到默认值，刚调好的预算也丢了。范围是 gsb/batch50-py-game-b-10 的 vegetation_wind_driver.py，类 VegetationWindDriver，负责登记风场与植被实例、按世界坐标采样风场、按距离分档降频更新并在每帧预算内截断；这些入口目前在代码里没有任何行为，一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：VegetationWindDriver(*, frequency=0.35)；register_field(field_id, *, wavelength, phase=0.0)、register_instance(instance_id, *, position, stiffness=1.0, field)、set_wind(strength, direction, *, transition=0.0)、set_lod_budget(per_update, *, near_radius=30.0, far_stride=3)、update(time)、sample_instance(instance_id, time)、batch_of(time)、phase_of(instance_id)、stats()、snapshot()、restore(state)。拒绝一律抛 WindDriverError(code, detail)。

故障与边界：①register_field 要求 field_id 去空白后非空且不重复、wavelength 为有限正数、phase 为有限数，违反报 WIND_INVALID_INPUT；②register_instance 要求 instance_id 去空白后非空且不重复、position 是 2 个有限数值、stiffness 是有限正数、field 必须已登记否则报 WIND_UNKNOWN_FIELD；实例相位由 id 的加权校验和生成，第 i 个字符权重为 i+1，求和后对 1024 取余，再除以 1024 乘 2π 并保留 6 位小数；到原点距离小于 near_radius 记为 near，否则 far；③set_wind 要求 strength 为有限非负数、direction 为有限数并按 360 取模归一、transition 为有限非负数，违反报 WIND_INVALID_WIND，返回 strength、direction、transition 三个键；④set_lod_budget 要求 per_update 与 far_stride 是正整数、near_radius 是有限正数，违反报 WIND_INVALID_BUDGET，返回三个键，改半径后实例按新半径重新分档；⑤未设风时 update 报 WIND_NOT_SET，time 必须是有限数且不得小于上一次 update 的时间，违反报 WIND_INVALID_TIME，同一时刻重复 update 允许；⑥update 每调用一次算一个更新序号（从 1 起），near 实例每次进候选，far 实例只在序号减一能被 far_stride 整除时进候选，候选按到原点距离升序、距离相同按 id 升序，取前 per_update 个真正更新，其余计入 deferred，返回 updated、deferred、due；⑦每个实例最多保留最近两次更新结果，同一次 update 内每个实例最多更新一次；⑧sample_instance 在实例不存在时报 WIND_UNKNOWN_INSTANCE、从未更新过时报 WIND_NO_SAMPLE、time 非有限时报 WIND_INVALID_TIME；正好命中某次更新结果时原样返回，早于最早样本或晚于最近样本时贴到端点、不插值也不外推，落在两次更新之间时按时间比例线性插值振幅与摆角、interpolated 为 True，phase 始终按 2π 乘 0.35 乘 time 加实例相位后对 2π 取模；⑨降频实例在两次更新之间必须按线性插值补齐姿态，不允许一直停在旧样本、到下一次采样值才阶跃过去；⑩风场换向时摆动相位保持连续，振幅必须按 transition 指定的衰减时间平滑过渡，只有 transition 为 0 才允许立即生效；⑪batch_of 按距离与 id 升序返回全部实例在给定时刻的姿态，任一实例没有样本时直接报 WIND_NO_SAMPLE，不静默跳过；⑫快照固定为 version、fields、instances、wind、previous、budget、time、update_index、poses、counters 十个键，整体是深拷贝，restore 校验结构（poses 只能引用已登记实例、时间升序、更新序号与计数为非负整数），缺键、版本不符或类型不对报 WIND_SNAPSHOT_INVALID 且原状态不被改动；恢复后风参数、预算、相位、最近两次样本与累计计数都要继续可用，重启后不需要重新登记就能继续 update 与采样。

硬约束：同一实例被多路线程并发 update 时只能串行生效，更新计数与实际更新次数一致，单个实例在一次 update 里最多产生一份样本；快照与恢复要在同一把锁内完成，恢复失败时风参数、预算、样本与计数都不留半截改动；每帧更新数是硬预算，不得超过 per_update，也不许为了补齐远处实例而偷偷多算。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；题面点到的每一项都要落到代码行为上；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: vegetation_wind_driver
- typeName: VegetationWindDriver
