# batch50-py-game-b-08-p5

## 题面

角色和武器这批资产上线后，法线贴图在高光处整块翻黑，镜像 UV 的半边身体方向相反；DCC 导出的网格里夹着几个 UV 面积为零的三角形，重建一次切线就把这些顶点原有的切线抹成零，表面直接塌陷；硬边处的切线断开没有拆点，倒角看着像被磨平；美术改完 UV 重新导入，缓存还吐旧结果；进程重启后版本号从一重数，和美术工具里的版本对不上；这批资产还要过法线贴图验收，切线方向错一点都会被退回。范围是 gsb/batch50-py-game-b-08-p5 的 tangent_frame_builder.py，类 TangentFrameBuilder，依据三角形 UV 导数重建逐顶点切线与副切线，累加后正交化，遇到镜像 UV 或硬边切线断裂时拆点并写入手性符号，结果按网格版本与 UV 通道缓存。

公开接口：TangentFrameBuilder(*, max_vertices=4096)；register_mesh(mesh_id, *, positions, uvs, indices, normals=None, uv_channel=0, material_groups=None)；set_uv_channel(mesh_id, channel, uvs)；build_frames(mesh_id, *, uv_channel=0)；split_vertices(mesh_id, *, uv_channel=0, angle_threshold=60.0)；validate(mesh_id)；cache_key(mesh_id, uv_channel=0)；invalidate(mesh_id)；mesh_info(mesh_id)；set_max_vertices(limit)；snapshot()；restore(state)；stats()。所有拒绝统一抛 TangentError(code, detail)。

故障与边界：①顶点与 UV 数量必须一致，索引长度为三的倍数且全部落在顶点范围内，normals 与 material_groups 若给出长度必须匹配，违规报 TANGENT_INVALID_REQUEST，顶点数超过 max_vertices 报 TANGENT_VERTEX_LIMIT，set_max_vertices 只接受正整数；②每个三角形按 UV 导数求切线与副切线并累加到三个顶点，再对顶点法线正交化，手性符号按副切线与法线叉积的符号写进切线第四个分量，切线空间必须是右手系，单位化后不得留下零向量；③同一网格重复注册版本加一并作废该网格全部缓存，register_mesh 返回新版本号，cache_key 形如 网格号:v版本:uv通道，mesh_info 返回 mesh_id、version、vertex_count、triangle_count 与 uv_channels，uv_channels 以升序元组返回；④build_frames 对同一版本与通道只算一次，再调用带 cached 为真，结果含 mesh_id、version、uv_channel、tangents、indices、vertex_count、triangle_count、cache_key，indices 与 tangents 以元组返回，缓存结果与重新计算的结果逐分量一致；⑤UV 面积为 0 的三角形不得参与切线累加，也不能把已有切线清零；⑥同一顶点被正反两套 UV 共享时必须拆点，并逐顶点写入手性符号；⑦顶点拆分后的索引重映射要保留原三角形绕序与材质分组边界；⑧set_uv_channel 新增或替换通道时校验 UV 数量、返回新版本号并让版本加一，构建未知通道报 TANGENT_INVALID_REQUEST；⑨invalidate 返回清掉的条目数，未知网格的读取、构建、失效一律报 TANGENT_UNKNOWN_MESH；⑩validate 返回 valid、vertex_count、triangle_count、degenerate_uv_triangles、mirrored_triangles，只做检查不改状态；⑪snapshot 返回 {"schema","meshes","cache","stats"} 深拷贝，restore 结构非法报 TANGENT_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 meshes、versions、builds、cache_hits、invalidations、vertex_limit_refusals。

硬约束：同一网格的构建必须串行，多线程同时请求只能真正计算一次，其余命中缓存且结果完全一致；重启恢复后网格版本、UV 通道与缓存条目都要在，且不与调用方共享结构；顶点上限与拆分后的顶点总数都是硬顶，构建失败不得留下半份缓存。

验收：python3 -m pytest -q tests 的 15 条用例必须全部通过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: tangent_frame_builder
- typeName: TangentFrameBuilder
