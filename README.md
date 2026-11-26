# batch50-py-game-b-05-p5

## 题面

图标系统改走矢量路径之后，QA 提了一串渲染问题：圆角图标放大到 4K 后边缘是一段段折线，看起来像没开抗锯齿；自相交的五角星徽章填充时中间破了一个洞，露出背景；虚线描边的环形进度条在闭合处出现双倍间隔，转一圈会明显卡一下；还有几个复杂徽章直接把顶点预算打满，路径尾部被削掉一截。范围是 gsb/batch50-py-game-b-05-p5 的 vector_path_tessellator.py，类 PathTessellator，把带贝塞尔段的路径按屏幕空间容差扁平化为折线，按填充规则生成填充三角形，并处理描边宽度、连接样式与虚线相位。

公开接口：PathTessellator(*, max_vertices=4096, cache_vertex_budget=65536, default_tolerance=0.5)；begin_path、move_to、line_to、cubic_to、close、set_style、path_view、cache_key、tessellate、release_path、cache_usage、snapshot、restore、stats。拒绝一律抛 TessellationError(code, detail)。

故障与边界：①begin_path 建一条空路径，重复 ID 报 PATH_EXISTS，空路径名报 PATH_INVALID_REQUEST，未登记的路径一律 PATH_UNKNOWN；②一条路径只允许一个子路径，line_to 之前必须先 move_to，重复 move_to、闭合之后继续落笔都报 PATH_INVALID_REQUEST；坐标必须是有限数值，字符串、NaN 与无穷同样拒绝；③close 要求子路径至少已有一段线或曲线，重复闭合报 PATH_INVALID_REQUEST；④cubic_to 的段按屏幕空间容差自适应细分，首末点与端点重合，容差收紧时细分点数只增不减；⑤容差默认取 default_tolerance，必须大于零且不超过 64，越界报 PATH_INVALID_TOLERANCE；⑥相邻重复点必须合并，degenerate_segments 报告被合并的段数；⑦闭合路径按 fill_rule 生成填充三角形，四个点的凸多边形恰好两个三角形，三角形下标必须落在顶点范围内，开放路径不产生填充；⑧set_style 的填充规则只接受 nonzero 与 evenodd，连接样式只接受 miter、bevel、round，描边宽度非负，虚线为一组正数且长度为偶数，非法报 PATH_INVALID_REQUEST；⑨描边宽度大于零时按连接样式生成四边形，stroke_quads 大于零，宽度为零时为零；⑩cache_key 由路径版本、样式与容差组成，同一组输入必须得到同一个字符串，几何或样式改动后必须变化；⑪tessellate 结果按 cache_key 缓存，重复调用 cached 为真且 points 与 triangles 逐项一致，cache_usage 给出 entries、limit、used_vertices、hits、misses、evictions；⑫snapshot 深拷贝 paths 与 stats，restore 结构非法报 PATH_SNAPSHOT_INVALID 且原状态不变，stats 至少含 paths、edits、tessellations、cache_hits、evictions、refusals。

硬约束：同一路径重复三角化必须逐字节一致，缓存按顶点总数封顶，淘汰不得让已经取出的结果变形，同一路径的并发请求只编译一次；容差过小导致顶点数超过 max_vertices 时要保持路径拓扑并降级为更粗容差继续细分，不能截断尾部；闭合路径的虚线相位按周长取模续接，闭合处不得出现双倍间隔；自相交路径按奇偶规则填充时，交叠区域的三角形绕序不能互相抵消出洞。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: vector_path_tessellator
- typeName: PathTessellator
