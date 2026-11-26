# batch50-py-safety-d-13

## 题面

GraphQL 网关连出两单：一条查询用几百个别名重复放大同一字段，深度与条数都没超，账单先炸；另一条持久化查询在客户端与网关指纹不一致，被近似匹配放行；批量按条数计费，单条超深也过了。范围是 gsb/batch50-py-safety-d-13 的 graphql_abuse_guard.py，类 GraphqlAbuseGuard。

接口：GraphqlAbuseGuard(*, cost_budget, depth_limit, burst, max_concurrent, strict_persisted, cost_per_token)；admit(query, *, client, now)；admit_batch(queries, *, client, now)；register_persisted(query=None, *, fingerprint=None)；revoke(fingerprint)；charge(client, cost, *, now)；拒绝抛 GraphqlGuardError(code, detail)。

边界：①深度按嵌套层算，片段展开计入。②循环片段拒绝。③代价 = 权重×(1+子树)，权重 1，列表子树乘 10。④超深度 DEPTH_EXCEEDED，超预算 COST_EXCEEDED 带原因。⑤严格模式只放行已注册指纹，未注册 PERSISTED_REQUIRED。⑥内省默认拒绝，policy 可开。⑦别名重复放大代价，深度不变也要按别名计。⑧片段多层复用膨胀，估算带上限并拒绝。⑨批量按总代价 BATCH_COST_EXCEEDED，令牌折算。⑩指纹忽略空白与字段序、保留参数值；跨端不一致拒绝而非近似匹配。⑪超额 RATE_LIMITED，charge 超额 QUOTA_EXHAUSTED 不扣额。⑫快照深拷贝白名单、额度与统计，非法 SNAPSHOT_INVALID。

硬约束：admit 的额度检查与扣减在 RLock 内原子，不得先查后扣；每次 admit 占一个并发位，complete 释放；批量一次扣减。stats 含 admitted、tokens_spent。

验收：`python3 -m pytest -q tests` 十五条全过；不改测试、不跳过、不写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- module: graphql_abuse_guard
- typeName: GraphqlAbuseGuard
