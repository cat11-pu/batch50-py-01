# batch50-py-safety-c-24

## 题面

邮件网关的情报队列这两周被反复投诉：一条短链跳了四跳之后落到一个陌生域名，队列把整条链判成恶意，业务申诉了半天才发现真正的问题只是跳出了授权域名范围；另一条链在两个域名之间来回跳，展开任务一直不返回，后面排队的 URL 全被堵住；还有一批常见域名每次都要重新展开，缓存里明明有结论，却因为 TTL 配错整片过期。范围是 gsb/batch50-py-safety-c-24 下的 url_reputation_queue.py，类名 UrlReputationQueue，负责 URL 归一化、按观测到的重定向链展开、环路与跳数限制、按域名的裁决缓存。

公开接口：UrlReputationQueue(*, hop_limit=5, allowed_domains=(), default_ttl=600, max_pending=32)；register_domain_policy(domain, *, ttl=None, verdict="benign")；submit(url, *, chain=(), now)；pending()；expand(job_id, *, now)；expand_result(job_id)；verdict(job_id)；cache_lookup(url, *, now)；expire(*, now)；jobs()；stats()、snapshot()、restore(state)。拒绝时抛 UrlQueueError(code, detail)。

故障与边界：①URL 归一化保留 http 与 https，其它 scheme 抛 URL_BAD_URL；主机名转小写，去掉 80 与 443 默认端口并保留显式非默认端口，去掉 fragment，路径按点段归一，空路径补成“/”，带用户口令的 URL 一律拒绝。②chain 里每个条目都必须是可归一化的绝对 URL，出现非法条目抛 URL_BAD_CHAIN，且整次提交不得留下排队任务。③归一化后相同的 URL 只保留一个排队任务，后提交的返回同一个 job_id；任务号从 JOB-0001 递增，排队上限为 max_pending，超限抛 URL_QUEUE_FULL，展开后名额立即释放。④expand 只处理排队中的任务，未知任务抛 URL_JOB_UNKNOWN，已展开的任务重复调用返回原结果且不重复计数；submit 返回 job_id、url、state，jobs 返回每项的 job_id、url、state。⑤展开从提交的 URL 开始沿 chain 逐个跟随，hops 只统计实际跟随的跳数，chain 元组首元素是归一化后的提交 URL，末元素是最后落点。⑥链路回到已经访问过的 URL 判为环路，outcome 为 loop、verdict 为 undetermined、原因为 redirect_loop，不得判成恶意也不得写入缓存。⑦跳数上限为 hop_limit，超出的那一跳不得跟随，outcome 为 hop_limit、verdict 为 undetermined、原因为 hop_limit，final_url 为空。⑧重定向跳出授权域名范围时要停止展开并标记越界，outcome 为 out_of_scope，不得继续跟随后续跳，也不得把越界结果当成恶意结论。⑨全部跳都在范围内时 outcome 为 resolved，裁决取末跳主机的域名策略，未登记策略按 benign 处理、原因为 default_policy，登记了策略原因为 domain_policy。⑩缓存只保存 resolved 结论，键为完整的归一化 URL，有效期取末跳主机策略的 ttl，未配置时取 default_ttl；命中未过期缓存时 submit 直接返回 state 为 cached、job_id 为空，且不占用排队名额。⑪缓存命中但已过 TTL 时需回源重新展开，不得沿用旧裁决，回源期间其它 URL 的提交与查询不得被阻塞；expire 只删除到期条目并返回删除条数。⑫verdict 与 expand_result 对未展开任务抛 URL_JOB_PENDING，未知任务抛 URL_JOB_UNKNOWN；cache_lookup 返回 verdict 与 expires_at；stats 返回 policies、submitted、expansions、cache_hits、expired、undetermined 六项；非法快照抛 URL_SNAPSHOT_INVALID，且不得改动现有策略、任务与缓存；快照键为 format、policies、jobs、cache、counters。

硬约束：同一 URL 的并发提交必须合并成一次展开，排队、任务号分配与缓存写入之间不得插入重复条目；快照必须与活动状态完全脱钩，恢复后域名策略、排队任务、已展开结果、缓存有效期与六项计数原样回来，已展开任务不得借快照回到排队状态。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: url_reputation_queue
- typeName: UrlReputationQueue
