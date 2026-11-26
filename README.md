# batch50-py-safety-c-09-p2

## 题面

大页池这台机器最近被内存组投诉得很厉害：同一个 NUMA 节点上的空闲大页明明还够，业务申请四页却一直报失败，查下来是被拆成两段两页的空洞，谁也不敢动，碎片只能靠人工挑维护窗口重启整机来消掉，每次都要停半个小时的业务；另一次更糟，某个租户的配额早就用满了，值班的人看池子整体还有余量就直接放行，结果这个租户把整台机器的份额吃光，其他业务全部 OOM；还有释放过的页要等下一次重启才能被重新申请到，节点之间的页也被悄悄挪来挪去，这几件事每周都在重复，运维只能手工记表格核对。范围是 gsb/batch50-py-safety-c-09-p2 下的 hugepage_pool_warden.py，类 HugepagePoolWarden，负责按节点维护大页池、租户配额、连续分配与碎片整理核算。

公开接口：HugepagePoolWarden()；add_node(node, pages)；register_tenant(name, *, quota)、set_quota、tenants()；allocate(tenant, count, *, node) 返回 Allocation（alloc_id、tenant、node、start、count）；release(alloc_id, *, tenant) 返回释放页数；defrag(node) 返回合并次数；usage(tenant=None)；node_view(node) 返回 NodeView（node、total_pages、free_pages、fragments、allocations）；allocation_info(alloc_id)；snapshot、restore、stats。拒绝时抛 HugepageError(code, detail)。

故障与边界：①节点页数为正、名称非空，重名报 HP_DUPLICATE_NODE，非法报 HP_INVALID_REQUEST，新节点初始是一整段从 0 开始的空闲段；②租户配额非负，重名报 HP_DUPLICATE_TENANT，未知租户报 HP_UNKNOWN_TENANT；set_quota 低于已用报 HP_INVALID_REQUEST 且原配额不变；③allocate 在指定节点上取起始地址最小的、长度足够的空闲段，从段首切走，余量成为该节点的新空闲段并保持升序；④申请页数非正报 HP_INVALID_REQUEST，未知节点报 HP_UNKNOWN_NODE；⑤节点空闲页总数不足报 HP_NODE_EXHAUSTED，空闲总数够但没有足够长的连续段报 HP_NO_CONTIGUOUS_RUN，两者不能混用；⑥租户已用加本次申请超过配额时一律拒绝并报 HP_QUOTA_EXCEEDED，池子整体还有余量也不放行；⑦释放必须带租户校验，非属主报 HP_NOT_OWNER 且分配不动，未知或已释放的编号报 HP_UNKNOWN_ALLOCATION；⑧释放的页立即回到该节点空闲段集合，同节点申请可以立刻复用，绝不跨节点挪用；⑨defrag 只合并同节点相邻空闲段，不移动任何已分配页，返回合并次数，再调返回 0；⑩usage 不带租户时按租户名升序返回各租户已用页数；⑪快照含 version、nodes、tenants、allocations、fragments、counters、next_alloc，allocations 以分配编号为键、值带 tenant、node、start、count，快照与内部状态不共享，restore 结构非法报 HP_SNAPSHOT_INVALID 且不动现有池子；⑫node_view 的 allocations 按起始地址升序，每项为起始页、页数与租户。

硬约束：并发申请同一节点不得重叠、不得超发，成功条数与页面占用必须对得上；快照恢复后节点空闲段、租户配额与已用、分配编号必须一致，恢复出来的结构与快照互不共享。只做本地实现，不得改测试、跳过或按固定输入写死；并发与重启自行验证。验收运行 python3 -m pytest -q tests，15 条全部通过。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: hugepage_pool_warden
- typeName: HugepagePoolWarden
