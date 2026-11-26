# batch50-py-game-b-04-p5

## 题面

换了顶点动画纹理之后，副本里的植被和布料被玩家挑出一堆毛病：单次播放的挥手动作播完会突然从头抽一下，人也跟着闪；循环的旗子在相位偏移为负的实例上跳一帧，两片旗子对不齐；美术重导了一个新版本的剪辑，场上已有的旧实例一半用新帧一半用旧帧，看起来像在抽搐；同屏实例一多帧率就掉到二十以下，重启之后所有实例的播放进度又归零。范围是 gsb/batch50-py-game-b-04-p5 的 vertex_animation_sampler.py，类 VertexAnimationSampler，按剪辑元数据把顶点动画纹理采样成每实例的顶点位置，供渲染线程逐帧取用。

公开接口：VertexAnimationSampler(*, max_instances=256, max_state_cache=128)；register_clip、clip_view、acquire_instance、instance_view、set_phase、advance、sample_frame、sample_position、release_instance、cache_usage、snapshot、restore、stats。拒绝一律抛 VertexAnimError(code, detail)。

故障与边界：①登记时帧数不少于两帧、帧率大于零、包围盒三个轴的最小值都要小于最大值、探测点轨迹每帧一个三元组且条数等于帧数；②同 ID 同版本重复登记报 VERTANIM_CLIP_EXISTS，空剪辑名与参数非法报 VERTANIM_INVALID_REQUEST；③clip_view 给出帧数、帧率、时长（帧数减一除以帧率）、包围盒、是否含法线与当前实例数，版本号随登记保留；④acquire_instance 的模式只接受 loop、once、clamp，未知模式报 VERTANIM_INVALID_REQUEST，未知剪辑报 VERTANIM_UNKNOWN_CLIP，重名实例报 VERTANIM_INSTANCE_EXISTS；⑤实例总数受 max_instances 限制，超限报 VERTANIM_INSTANCE_LIMIT，释放后可再申请，重复释放报 VERTANIM_UNKNOWN_INSTANCE；⑥advance 只接受非负秒数，负值报 VERTANIM_INVALID_REQUEST，时间按实例累计，统计里 advances 逐次加一；⑦sample_frame 返回 frame、next_frame、alpha、local_time、finished，采样落在两帧之间时按位置取整与取小数；⑧时间正好落在整帧上时 alpha 为零、frame 取该帧、next_frame 取下一帧；⑨sample_position 在相邻两帧的探测点之间做线性插值；⑩相位以剪辑时长的比例给出，采样起点整体后移，set_phase 传非数值报 VERTANIM_INVALID_REQUEST；⑪状态槽以（剪辑、模式、归一相位）为键共享，每个实例只独享自己的时间，缓存上限为 max_state_cache，超限淘汰最久未用的槽，cache_usage 给出 entries、limit、hits、misses、evictions；⑫snapshot 深拷贝 clips、instances 与 stats，restore 结构非法报 VERTANIM_SNAPSHOT_INVALID 且原状态不变，stats 至少含 clips、instances、acquires、advances、samples、releases、refusals。

硬约束：同一实例的并发 advance 必须串行，累计时间与计数不能丢；单次模式播到末帧后继续 advance 必须停在末帧，不得越界采样下一帧；循环模式相位为负或超过一周时按取模归一，插值不得跨剪辑首尾产生跳变；剪辑重新注册为新版本后，旧实例要么整体迁移要么明确报错，不能混用两版帧数据；状态槽被淘汰后实例的播放进度仍要可恢复，重新采样按自己的时间重建，不回到起点。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: vertex_animation_sampler
- typeName: VertexAnimationSampler
