# batch50-py-game-b-03

## 题面

烘焙农场这周连续爆单：同一张场景反复提交同一块区域的烘焙，队列里堆了几十份重复任务，两个工作线程同时领到同一块，产出互相覆盖；图集页只有一张 1024×1024，放不下的结果被静默丢掉，地面出现黑块。场景改一盏灯后整张图集全量重烘，一晚上没跑完；美术手动取消的烘焙，完成回包还是把旧结果写了回去。农场同时挂着三台机器，单机最多排 64 块，超出就直接丢单。范围是 gsb/batch50-py-game-b-03 的 lightmap_bake_queue.py，类 LightmapBakeQueue，负责任务排队、工作线程领取、图集页货架式打包与脏区合并。

公开接口：LightmapBakeQueue(*, page_size=(1024, 1024), max_queued=64)；submit(scene, region, *, priority=0, size)；cancel(task_id)；claim(worker_id)；complete(task_id, *, digest)；pack_atlas()；dirty_mark(scene, region)；merge_dirty(scene)；snapshot() 与 restore(state)；stats()。拒绝一律抛 BakeError(code, detail)。

故障与边界：①任务键为 (scene, region)，同键还在排队、运行或取消中时重复 submit 返回原任务且 submitted 不增加，已完成或已取消后可以重新提交并分配新号，任务号形如 bake-0001、四位序号自增，submit 返回 task_id、scene、region、priority、size、status 字段；②priority 越大越先出队，同优先级按任务号先来先服务；③claim 每次只把一块任务置为 running 并绑定 worker，同一 worker 已持有任务时抛 BAKE_WORKER_BUSY，队列为空返回 None，worker 为空抛 BAKE_INVALID_ARGUMENT；④complete 只接受 running 任务且 digest 非空，完成后释放 worker 并把 worker 置空，对排队或已完成任务调用抛 BAKE_NOT_RUNNING，未知任务抛 BAKE_UNKNOWN；⑤cancel 只对排队任务生效并释放队列位，已完成或已取消抛 BAKE_NOT_CANCELLABLE；⑥运行中的任务被取消后进入 cancelling，完成回调到达时不写回结果但仍归还占用的槽位；⑦图集按完成顺序做货架式打包：页内维护 x 游标与当前行高，放不下宽度就换行，换行后高度放不下就新开页，区域绝不拆分、绝不丢弃；pack_atlas 返回页对象列表，每页含 page 与按放置顺序的 (region, rect) 列表，rect 为 (x, y, w, h)；⑧同一区域只打包一次，再次 pack_atlas 返回空列表，页号连续递增；⑨脏区按图集矩形的共享边做四邻接传递合并，跨页即使坐标相同也不合并，dirty_mark 返回当前场景的脏区数量，merge_dirty 返回分组列表，每组含 page、regions（元组）与 bounds（元组），分组按页号再按最小 region 升序，并清空脏集合，无脏区时返回空列表；⑩脏区合并后只重烘受影响的图集页，未受影响页保留旧数据并在 reused_pages 中标记复用；⑪快照键为 version、page_size、max_queued、tasks、atlas、dirty、stats，保存排队任务、运行租约、已完成结果、图集页、脏区与计数，统计计数不得为负，恢复非法结构抛 BAKE_SNAPSHOT_INVALID 且现场不变；⑫size 必须是两个正整数的元组且不超过页尺寸，越界抛 BAKE_INVALID_ARGUMENT，排队超过 max_queued 抛 BAKE_QUEUE_FULL。stats 返回 submitted、claimed、completed、cancelled、discarded、packed_regions、pages、reused_pages。

硬约束：同一任务不能被两个 worker 同时领取，租约转移必须先完成或取消；取消中的完成回调不得写回结果，但必须归还槽位，否则队列永久少一格。图集打包是幂等的，任意次重复调用都不能产生重复区域，页号只能单调增加。恢复快照后旧的 worker 租约不能重复分配，也不能让同一 worker 同时持有两格。

验收：python3 -m pytest -q tests 必须 15 条全过；不得改测试、跳过、按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: lightmap_bake_queue
- typeName: LightmapBakeQueue
