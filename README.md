# batch50-py-game-b-06

## 题面

美术组在夜间关卡验收时撞上两件互相矛盾的事：同一时刻切镜头，天边会闪出一条明显的亮线，换个方位那条线又跑到别处；另一拨人报的是切天气预设后帧率掉一截、几秒恢复，但天顶颜色和开机时对不上，反复切同一个预设还一直掉帧。范围是 gsb/batch50-py-game-b-06 的 atmosphere_scatter_cache.py，类 AtmosphereScatterCache，把大气散射查找表按太阳高度角和方位角分桶缓存、按天气只重建受影响的桶、缓存满了按使用频率淘汰；这些入口目前在代码里没有任何行为，一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：AtmosphereScatterCache(*, capacity=8, samples=8, boundary_tolerance=5.0)；set_sun(altitude, azimuth)、bucket_for(altitude, azimuth)、build(altitude, azimuth)、lookup(altitude, azimuth, index)、invalidate(altitude, azimuth)、set_weather(preset)、resize(capacity)、stats_of(altitude, azimuth)、snapshot()、restore(state)、stats()。拒绝一律抛 AtmosphereCacheError(code, detail)。

故障与边界：①高度角自 -90 度起每 5 度一桶共 36 个，方位角自 0 度起每 15 度一桶共 24 个，高度角必须落在 [-90, 90]、方位角必须落在 [0, 360)，越界或任一角为 NaN 报 ATMOSPHERE_INVALID_ANGLE；②桶的几何中心是该桶的代表角度，桶内表值是 samples 个整数，第 i 个按（高度桶号×1000 + 方位桶号×37 + i×3）乘天气密度再整除 1000 得到，密度 clear 为 1000、hazy 为 1400、overcast 为 1800，未知预设报 ATMOSPHERE_UNKNOWN_PRESET；③同一太阳角度重复 set_sun 必须落到同一个桶且不触发重建，build 同一个桶第二次直接返回缓存值，builds 只统计真正生成过的次数；④lookup 的 index 必须落在 [0, samples) 内，越界报 ATMOSPHERE_INVALID_INDEX，角度不合法或 index 越界时不得生成任何桶、也不得改动任何计数；请求角度正好落在桶中心时直接取该桶表值，否则取相邻桶中心做插值并保留 4 位小数；⑤相邻桶表值在该点相差超过 boundary_tolerance 时按插值结果返回，同时给请求所在的桶记一次边界回退，回退次数按桶独立累计，不许摊到相邻桶上；⑥每个桶有独立的 builds、lookups 与边界回退计数，stats_of 对从未生成过的桶返回 cached 为 False、values 为 None、各计数为 0，不报错；⑦缓存容量以桶为单位，超容量时淘汰使用次数最少的桶，次数相同时淘汰更早生成的桶，淘汰只清缓存、计数保留；被淘汰的桶再次请求时重建的表值必须与首次生成逐值一致，不得因复用旧缓冲残留上一个桶的数据；⑧resize 收缩按同一淘汰规则压到新容量并返回淘汰数，非法容量报 ATMOSPHERE_INVALID_CAPACITY 且容量不变，扩容不重建任何桶；⑨invalidate 只对已缓存桶生效并返回 True，重复失效返回 False，下次 lookup 或 build 重新生成、builds 加一；⑩天气切换只影响高度角中心低于 10 度的桶：这些桶立即退出缓存、下次访问按新密度重建，更高处的桶原样保留（表值与计数不动），set_weather 返回退出缓存的桶数，同一预设重复设置返回 0、也不计入天气切换次数；⑪快照固定为 version、weather、sun、settings、buckets、registry、counters 七个键，settings 含 capacity、samples、boundary_tolerance，counters 含 builds、evictions、lookups、invalidations、weather_changes、build_seq，整体是深拷贝，restore 校验结构，缺键、版本不符或类型不对报 ATMOSPHERE_SNAPSHOT_INVALID 且原状态不被改动；⑫恢复后表值、使用次数、淘汰次序与边界回退计数都要继续可用，重启不能把缓存清空。

硬约束：多路线程同时请求同一个还没生成的桶时只能有一次真正的表计算，其余请求拿到同一份值，builds 不得翻倍，也不许有线程读到算了一半的表；快照与恢复必须在同一把锁内完成，恢复失败时缓存、计数、天气与设置都不留半截改动；同样的角度与天气序列跑两遍，数值、淘汰顺序与计数必须逐项一致。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；题面点到的每一项都要落到代码行为上；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: atmosphere_scatter_cache
- typeName: AtmosphereScatterCache
