# batch50-py-safety-c-17

## 题面

情报组这周的合并结果被下游连着退回来三次。第一次是同一条域名在两个源里都是黑的，合并后置信度反而比单源还低，上游以为我们做了平均；第二次是某家供应商的白名单条目被别家情报源盖成了拦截，客户投诉业务域名被误杀；第三次更隐蔽，一个指标过期后同一家源又报了一次，置信度却沿用旧值一路往下掉，值班同事看着零点几的分数不敢下结论。范围是 gsb/batch50-py-safety-c-17 的 ioc_feed_merger.py，类名 IocFeedMerger，负责来源登记、指标归一、按来源权重合成置信度、按 TTL 衰减以及恶意与白名单的优先级裁决。

公开接口：IocFeedMerger(*, halflife_seconds=86400, batch_limit=32)；register_source(name, *, weight, priority, kind, now) -> SourceRecord；ingest_feed(source, items, *, now) -> dict；merge(*, now) -> list[dict]；lookup(ioc_type, value, *, now) -> dict；effective_confidence(ioc_type, value, *, now) -> float；expire_sweep(*, now, batch_size=None) -> list[str]；sources()；audit()；stats()；snapshot()；restore(state)。拒绝时抛 IocError(code, detail)。

故障与边界：①指标类型只认 domain、ipv4、sha256、url，其它类型抛 IOC_BAD_TYPE；值归一后为空抛 IOC_BAD_VALUE；ttl 限 60 到 2592000 秒，越界抛 IOC_BAD_TTL；confidence 必须落在 0 到 1 之间，越界抛 IOC_BAD_CONFIDENCE。②来源权重取 0 到 1 的开区间、优先级 0 到 100、kind 只认 intel 与 whitelist，越界或重名分别抛 IOC_BAD_SOURCE 与 IOC_DUPLICATE_SOURCE；未登记来源送数据抛 IOC_UNKNOWN_SOURCE。③归一规则：域名去空格转小写并去掉末尾的点；IPv4 走标准库规范化；URL 整体转小写；sha256 统一小写。④同一来源对同一指标重复上报只保留一条观测，用新值覆盖旧值，不重复计数。⑤多源合并按噪声或合成置信度并取最长 TTL；merge 结果按类型与值升序排列。⑥只有白名单来源命中的指标裁决为放行，不写冲突留痕。⑦恶意与白名单同时命中时按来源优先级裁决，同优先级按拦截处理，并写一条 reason 为 priority_conflict 的留痕，记录类型、值、来源与胜出方。⑧白名单来源优先级高于情报来源时，不得因为另一方置信度更高就把结论翻成拦截。⑨指标过期后由同一来源重新导入，置信度要回到该来源的初始值，不能沿用旧的衰减结果。⑩effective_confidence 按剩余 TTL 比例线性衰减，到期时为 0。⑪expire_sweep 按 batch_size 分批清理过期观测并返回本轮清掉的键，未到期的观测一条都不能动，分批是为了不阻塞查询。⑫统计给出 sources、observations、indicators、accepted、rejected、swept、conflicts、merged_indicators 八项。

硬约束：同一指标的写入、合并与清扫必须串行，清扫一轮只处理一个批次且不改变未到期数据；快照与活动状态完全脱钩，恢复后来源、观测、到期时间、裁决留痕与计数原样回来，非法快照抛 IOC_SNAPSHOT_INVALID 且不改动现有数据，重启后不得把已清扫的观测借快照带回来。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: ioc_feed_merger
- typeName: IocFeedMerger
