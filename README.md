# batch50-py-game-b-06-p5

## 题面

烘焙农场这周连着返工：同一场景对象被两个作业同时写进同一张光照贴图页，出图后是一整片花斑；美术把纹素密度调高之后，系统仍旧在原来的小槽位上硬采样，模型表面出现明显的拉伸锯齿；作业被人取消后重新排队，同一块区域没清理就覆写，接缝处留着上一轮的灰边；服务重启回来所有进度归零，只剩几张成品摘要对不上账，只好整张重烤。范围是 gsb/batch50-py-game-b-06-p5 的 lightmap_bake_scheduler.py，类 LightmapBakeScheduler，按对象包围盒和纹素密度分配页槽，按优先级派发到有限工作槽，并记录每个作业的页进度与产物摘要，供烘焙农场与对账脚本共用。

公开接口：LightmapBakeScheduler(*, page_slots=4, max_pages=8, max_workers=2)；submit_job(object_id, *, texel_density, bounds, priority=0)；allocate_page(job_id)；start_job(job_id, *, worker)；dispatch(worker)；report_progress(job_id, *, page_index, progress, digest=None)；cancel_job(job_id)；resume(job_id)；fail_job(job_id, *, reason)；release_worker(worker)；job_state(job_id)；pages_of(object_id)；pending_jobs()；snapshot()；restore(state)；stats()。作业句柄形如 job-0001，按提交序号递增；页分配结果用 PageAllocation(page, slots, slot_texels=512) 表示。所有拒绝统一抛 LightmapError(code, detail)，调用方按 code 分支处理。

故障与边界：①所需槽位数按包围盒宽高乘纹素密度再除以 512 向上取整，至少一个；超过单页槽位上限报 LIGHTMAP_DENSITY_TOO_HIGH，不得建页；②allocate_page 按页号升序、槽号升序首次适配，单页放不下就开新页，页数封顶后报 LIGHTMAP_PAGES_EXHAUSTED 并计 refused_allocations；③对象缩放后密度提高、原槽位放不下时，必须换页并把旧页片段作废，禁止把原槽位拉伸采样；④同一对象用完全相同的参数重复提交，必须返回原句柄，不得新建第二份作业；⑤dispatch 只挑已分配且排队的作业，priority 大者先，同级按提交序号，无活可派返回 None，工作槽已占用报 LIGHTMAP_WORKER_BUSY，超过 max_workers 报 LIGHTMAP_WORKER_LIMIT；⑥start_job 要求作业已分配页且工作槽空闲，未分配报 LIGHTMAP_JOB_NOT_ALLOCATED，工作槽相关错误与 dispatch 共用 LIGHTMAP_WORKER_BUSY 和 LIGHTMAP_WORKER_LIMIT，release_worker 把运行中的作业退回 queued；⑦report_progress 只接受 running 作业，页号必须落在分配到的槽位内，进度在 0 到 1 之间且同页不得回退，违规报 LIGHTMAP_PROGRESS_INVALID，作业不在运行报 LIGHTMAP_JOB_NOT_RUNNING；⑧所有页进度到 1 后作业转 done、释放工作槽，digest 按页序保存成元组，未提供 digest 的页在元组里留 None，completed 加一，job_state 返回 object_id、status、priority、required_slots、page、slots、worker、version、attempts、progress 与 digest；⑨cancel_job 可取消 queued 与 running，释放工作槽但保留页分配和进度，已写入的页片段必须标脏，resume 先清脏再重写同一区域，不得另起新页，resume 只接受 canceled 作业并恢复成 queued，其余状态报 LIGHTMAP_NOT_CANCELED；⑩fail_job 只接受 running 作业，转 failed、attempts 加一、释放工作槽与全部页槽位，之后仍可 allocate_page 重试；⑪空对象名、非正密度、包围盒不是两个正数、负优先级报 LIGHTMAP_INVALID_REQUEST，未知句柄报 LIGHTMAP_UNKNOWN_JOB；⑫snapshot 返回 {"schema","jobs","pages","workers","stats"} 的深拷贝，restore 结构非法报 LIGHTMAP_SNAPSHOT_INVALID 且原状态不变，stats 含 submitted、allocations、dispatches、progress_reports、completed、canceled、resumed、failed、refused_allocations、pages_created。

硬约束：并发提交、分配、派发、报进度必须在同一把锁内完成，同一对象不得同时被两个作业占用，多线程分配不能拿到同一页同一槽；快照恢复后页占用、工作槽、进度与各项计数一致，且不与调用方共享可变结构；页数与同时在线工作槽数都是硬顶，取消和失败不得泄漏槽位。

验收：python3 -m pytest -q tests 的 15 条用例必须全部通过；不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现，不依赖外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: lightmap_bake_scheduler
- typeName: LightmapBakeScheduler
