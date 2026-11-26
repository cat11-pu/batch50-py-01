# batch50-py-game-b-01-p5

## 题面

体素大地图这周连着出故障：相机推到城区中心，画面里整片砖块变成洋红色，日志说砖池已满，可同一帧里另有几块砖明明没人用；两张地块来回切换后，切回来的一半体素是空的，要退出重进才恢复；维护重启后驻留状态全丢，已经在池里的砖要重新上传一遍，最长一次卡了三秒；对账时发现砖池报的字节数和实际驻留的砖对不上，排查到驻留这一段的状态维护各写各的。范围是 gsb/batch50-py-game-b-01-p5 的 svo_residency_manager.py，类 SvoResidencyManager，维护每个场景体素的稀疏八叉树节点、砖块驻留与引用计数，供地形流式加载和相机裁剪共用。

公开接口：SvoResidencyManager(*, brick_pool_bytes=1048576, brick_bytes=4096, max_depth=6, max_nodes=4096)；declare_volume、volume_view、request_node、release_node、split_node、merge_node、tag_node、evict、brick_usage、resident_keys、node_state、attach_lod、detach_lod、snapshot、restore、stats。拒绝一律抛 SvoError(code, detail)。

故障与边界：①同一个地块被两路加载重复申请时引用计数只增不减，砖永远回收不了；②release 次数多于 request 必须报 SVO_REF_UNDERFLOW，不能把计数压成负数；③拆分出的 8 个子节点 morton 依次是父键乘八加序号，非叶子节点再拆报 SVO_ALREADY_SPLIT，已到卷深度报 SVO_DEPTH_EXCEEDED；④节点总数有上限，超限时整次拆分回滚，不留半截子树；⑤合并要求 8 个子节点都在、都是叶子、内容版本一致且引用计数为零，否则 SVO_NOT_MERGEABLE，合并后父节点取子节点最大内容版本，结构修订号前进一次；⑥砖池按字节封顶，申请时先按最近最少使用淘汰引用为零的砖，凑不出空位报 SVO_POOL_EXHAUSTED；⑦evict 按目标字节数淘汰，凑不够时砖池原样不动并报同一错误码，目标为零表示清空全部无引用砖；⑧brick_usage 分别给全池与单卷的已用、上限、空闲、驻留与缺砖数，resident_keys 按（层级、morton）升序；⑨上层 LOD 引用单独计数，attach_lod 与 detach_lod 成对使用，多拆一次报 SVO_INVALID_REQUEST；⑩未知卷、未知节点、空卷名分别报 SVO_UNKNOWN_VOLUME、SVO_UNKNOWN_NODE、SVO_INVALID_REQUEST；⑪snapshot 深拷贝 volumes 与 stats，restore 结构非法报 SVO_SNAPSHOT_INVALID 且原状态不变；⑫stats 至少含 volumes、requests、releases、splits、merges、evictions、refusals。

硬约束：同一卷上的并发申请与拆分必须在同一把锁里串行，返回后引用计数与砖池字节数要对得上，不能两条线程各看到半池空位；重启恢复后树结构、每节点引用计数、内容版本与驻留砖集合都要原样回来，不从恢复时刻重建根节点；合并收回的砖必须整枝归还砖池，子孙全部退出驻留；同一帧内先释放再申请同一个 morton 键不得触发重建，结构修订号只能前进；被淘汰的节点若仍被上层 LOD 引用，只能标为缺砖，树节点本身保留。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: svo_residency_manager
- typeName: SvoResidencyManager
