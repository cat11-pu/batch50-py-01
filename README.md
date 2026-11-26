# batch50-py-safety-b-10

## 题面

出站邮件网关最近被判了两次合规问题：一次是收件域策略只写了精确 MX，网关却把它的子域也当成匹配，邮件投给了不该投的主机；另一次策略已经过期，回源又失败，网关继续按 enforce 拒信，业务方积压了几百封退信。还有同域并发刷新把上游拉崩、报告表无限增长。值班同事还发现，同一个域在几分钟内被不同线程重复拉取，上游直接限流，后续其它域也拿不到策略。范围是 gsb/batch50-py-safety-b-10 的 mta_sts_enforcer.py，类 MtaStsEnforcer，负责拉取并缓存收件域 MTA-STS 策略、按 max-age 判定新鲜度、校验 MX 主机名并给出投递决策。

公开接口：MtaStsEnforcer(*, fetcher, cache_capacity=64, report_capacity=128)；fetch(domain, *, now=None, force=False)；decide(domain, mx_host, *, now=None)；refresh(domain, *, now=None)；policy_for(domain, *, now=None)；mx_matches(domain, host, *, now=None)；report()；purge_expired(now)；snapshot()、restore(state)、stats()。拉取失败或策略非法抛 StsError(code, detail)。

故障与边界：①fetch 校验版本、mode、max-age 与 MX 列表，按 fetched_at 加 max-age 计算 expires_at，合法才写入缓存，返回记录含 domain、policy_id、mode、max_age、mx、fetched_at、expires_at；版本必须是 STSv1，mode 只能是 enforce、testing、none，MX 列表不能为空且元素为合法主机名。②max-age 为 0 的策略立即失效，policy_for 在相同时刻就返回 None，decide 不得再按该策略判定。③缓存未过期时 fetch 直接返回缓存，不调用 fetcher；到期后必须回源；缓存命中要计入命中次数，不能把命中当成一次回源。④同域并发回源只能调用 fetcher 一次，其它调用等待并复用同一结果。⑤enforce 模式下 MX 命中返回 deliver、reason POLICY_MATCH；未命中返回 defer、reason MX_NOT_ALLOWED 并计入报告；报告按域累计 deliver、defer、opportunistic 三类结果，report 返回域到这三类计数的映射，供周报直接取用。⑥testing 模式下未命中仍然放行，但要标记 TESTING_MISMATCH 并记录失败，便于后续切 enforce。⑦mode 为 none 时一律放行并标记 POLICY_NONE；没有可用策略时返回 opportunistic、reason NO_POLICY，不能默认按 enforce 拒信；没有策略时也不主动回源，避免在投递路径上放大延迟。⑧MX 模式以 *. 开头时匹配一个或多个标签的子域；精确主机名只匹配完全相同的名字，通配子域匹配不得放行精确模式。⑨策略过期且再次拉取失败时退回机会式 TLS，不能继续按 enforce 拒绝；退回机会式后仍要保留失败计数，供下一次刷新参考。⑩策略非法或缺字段报 STS_POLICY_INVALID，拉取异常报 STS_FETCH_FAILED，两种情况都保留旧缓存并累加失败计数。⑪缓存超过 cache_capacity 按最后拉取时间淘汰；报告按域聚合并受 report_capacity 限制，超限的决策丢弃并计数。⑫快照含 version、policies、reports、failures、stats 五个顶层键并深拷贝，非法结构报 STS_SNAPSHOT_INVALID 且原状态不变。

硬约束：策略与失败计数要持久化，重启后缓存、报告与计数原样恢复；同域回源串行且只回源一次；缓存域名数与报告域数都有硬上限。stats 返回 fetched、cache_hits、failures、evicted、delivered、deferred、opportunistic、report_dropped。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: mta_sts_enforcer
- typeName: MtaStsEnforcer
