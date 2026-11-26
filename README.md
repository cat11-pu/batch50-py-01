# batch50-py-game-b-03-p5

## 题面

审片会上被指出一串色差问题：同一张纹理在美术显示器、现场投影和打样机上颜色对不上，换了显示器配置之后画面整体偏灰；用绝对比色输出的物料和设计稿有明显落差，日志却显示变换成功，没有留下任何提示；预览窗口偶尔闪一下变回未校色的样子，查下来是缓存把正在渲染的那一帧还在用的变换清掉了；进程重启后设备配置和已编译变换全部归零，冷启动第一次进游戏要卡两秒。范围是 gsb/batch50-py-game-b-03-p5 的 icc_transform_resolver.py，类 IccTransformResolver，负责设备 ICC 配置的登记与校验、按渲染意图构建色彩变换，供纹理上传与显示输出查询。

公开接口：IccTransformResolver(*, max_cache_entries=64, black_point_compensation=True, fallback_profile="srgb")；register_profile、profile_view、validate_profile、link_cache_key、resolve_transform、retain_handle、release_handle、invalidate_device、cache_stats、snapshot、restore、stats。拒绝一律抛 IccError(code, detail)。

故障与边界：①登记时设备名去空白后不得为空，设备类别只接受 input、display、output、colorspace，白点两个分量都要在零到一之间，色域标签不得为空，版本从 1 起；②同 ID 同版本重复登记报 ICC_PROFILE_EXISTS，参数非法报 ICC_INVALID_REQUEST；③内建 sRGB 配置以 colorspace 类别、版本 1 存在，任何回退都落到它；④validate_profile 对未知配置报 ICC_UNKNOWN_PROFILE，返回 valid、diagnostics 与 fallback，色域标签不在支持集合时 valid 为假、诊断码为 ICC_GAMUT_UNSUPPORTED、fallback 指向 sRGB；⑤link_cache_key 由源与目标的 ID 和版本、渲染意图、黑点补偿拼成，同一组输入必须得到同一个字符串，意图不区分大小写并归一为小写，未知意图报 ICC_INTENT_UNSUPPORTED，未知配置报 ICC_UNKNOWN_PROFILE；⑥perceptual、relative、saturation、absolute 四种意图各占独立键，黑点补偿默认取构造参数，显式传入时以传入值为准；⑦resolve_transform 命中缓存只加 hits，未命中同时加 misses 与 compiles，句柄带源与目标版本、意图、bpc、fallback 与诊断码；⑧坏配置参与解析时整体回退 sRGB，句柄 fallback 为真并保留诊断码，统计里 fallbacks 加一；⑨retain_handle 与 release_handle 维护在飞引用计数，引用减到负数或句柄不属于本实例时报 ICC_HANDLE_STALE；⑩invalidate_device 摘掉涉及该设备的缓存条目并按字典序返回键，配置本身保留，未知设备报 ICC_UNKNOWN_PROFILE；⑪缓存条目按上限封顶，超限淘汰最久未用条目，cache_stats 给出 entries、limit、hits、misses、compiles、evictions、invalidations、refusals；⑫snapshot 深拷贝 profiles、cache 与 stats，restore 结构非法报 ICC_SNAPSHOT_INVALID 且原状态不变。

硬约束：同一个缓存键的并发解析只允许编译一次，其余线程必须拿到同一份结果；设备配置被同 ID 的新版本替换后，旧变换只服务已经取出的句柄，新查询必须重新编译；目标配置缺少绝对比色所需的媒体白点时不得静默降级为相对比色，必须返回可区分的诊断码；缓存淘汰不得移除仍被在飞渲染帧引用的变换句柄。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: icc_transform_resolver
- typeName: IccTransformResolver
