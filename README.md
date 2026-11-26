# batch50-py-safety-b-01

## 题面

邮件网关这两个月的退信投诉一直压不下去：客户把发件域的 DMARC 策略从 p=none 调到 p=reject 之后，正常代发邮件被整批退掉，而真正伪造的邮件反倒经常放行；同一个域一会儿判隔离一会儿放行，值班同学复现不出来。范围是 gsb/batch50-py-safety-b-01 下的 dmarc_policy_evaluator.py，类 DmarcPolicyEvaluator，负责解析发件域发布的 DMARC 记录、缓存策略、对每封入站邮件给出对齐结论和处置动作，并把统计写入聚合报表。

公开接口：DmarcPolicyEvaluator(*, resolver=None, cache_ttl=300, negative_ttl=60, sample_salt="dmarc-v1", max_cache=256)；parse_record(domain, record_text)；organizational_domain(domain)；cache_policy(domain, record_text, *, now)；policy_for(domain, *, now)；invalidate(domain)；purge_expired(*, now)；evaluate(message, *, now=None)；report_aggregate(*, domain=None)；snapshot()、restore(state)、stats()。时间参数一律用带时区的 ISO-8601 字符串。resolver 是 callable(domain)->str|None，只有缓存未命中才调用。拒绝时抛 DmarcError(code, detail)。

故障与边界：①记录按分号切分，标签名转小写、值去空白，p 缺省 none，sp 缺省 inherit，pct 缺省 100，adkim 与 aspf 缺省 r，rua 去重后按字典序；②v 不是 DMARC1、p/sp 不是 none/quarantine/reject、pct 不在 0 到 100，抛 DMARC_INVALID_RECORD；③本域无记录时回退组织域记录，组织域默认取最后两段，命中 co.uk、com.cn、com.au、co.jp 后缀时取三段；④只有组织域记录时，子域的处置按 sp，sp=inherit 才回落到 p；⑤严格对齐要求 DKIM d= 或 SPF 域与 From 域完全相等，宽松对齐只要求组织域相同；⑥DKIM 与 SPF 任一通过对齐即 pass，两者都不通过为 fail，没有任何策略为 none；⑦pct 抽样的键由 salt、From 域、message_id 和策略域拼成后做 SHA-256，同一封邮件重复评估必须得到相同处置；⑧未命中抽样的邮件处置为 none，但评估结论仍是 fail；⑨unknown tag 要跳过继续解析，不能整条记录作废；⑩缓存按 TTL 过期，resolver 返回 None 时写入负缓存并按 negative_ttl 过期；⑪invalidate 命中返回 True，未命中返回 False；⑫report_aggregate 按域累计 pass、fail、none 与各处置数量，domain 为空时给全量。

硬约束：一是缓存与聚合计数必须线程安全，同一域并发评估只允许回源一次，策略与计数不能丢；二是 snapshot 固定包含 version、policies、aggregates、stats 四个键并返回深拷贝，restore 校验这四个键且版本必须为 1，结构不合法抛 DMARC_SNAPSHOT_INVALID 且不改动现有状态。stats 至少给出 evaluations、policy_hits、policy_misses、resolver_calls、invalidated、purged。

补充口径：message 是字典，至少含 from_domain、dkim_domain、spf_domain、message_id，两个域字段允许为 None；DmarcResult 至少暴露 result、disposition、dkim_aligned、spf_aligned、sampled、policy_source，policy_source 取 own、org、none。组织域回退只在本域完全没有记录时发生，子域自己有记录就用自己的记录，不和父域比优先级。抽样只影响处置，不影响对齐结论；聚合报表的 domains 下的每个小计要与总表同构，三个处置键始终存在，计数为 0 也要保留，切换策略后新邮件按新策略计，旧计数不清零。缓存里同一域只保留一条有效记录，invalidate 后重新回源拿到的新记录要覆盖旧 TTL；负缓存命中也算一次策略未命中，不能当成解析失败。策略域取实际提供记录的那个域，用于抽样键与报表归属。

验收：在包目录执行 python3 -m pytest -q tests，15 条必须全过；不得修改测试、跳过或用固定输入写死；并发与缓存过期自行验证；只做本地实现，不接外部服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: dmarc_policy_evaluator
- typeName: DmarcPolicyEvaluator
