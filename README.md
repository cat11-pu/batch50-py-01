# batch50-py-safety-c-28

## 题面

登录侧这周连续报障：一家集团把邮箱域名收归总部后，子品牌用户被路由到总部的身份源，原本单独的登录配置完全失效；两个租户互相声称同一个域名，解析结果每天在两边跳，用户时而登进 A 租户时而进 B 租户；身份源短暂不可用时登录页直接报错，没有降级路径；运维改了域名归属却发现要等很久才生效，查日志也说不清命中缓存还是现算。范围是 gsb/batch50-py-safety-c-28 下的 home_realm_router.py，类名 HomeRealmRouter，负责按邮箱域名做身份源发现、最长后缀匹配、冲突回退与解析缓存。

公开接口：HomeRealmRouter(*, default_realm="local", cache_ttl=300, max_domains=100)；register_domain(domain, *, tenant, realm, priority=0, now=None) 返回 DomainRule（含 domain、tenant、realm、priority、revision、state、updated_at）；resolve(email, *, now=None) 返回 Resolution；unregister_domain(domain, *, tenant, now=None)；refresh()；mark_unavailable(realm) 与 mark_available(realm)；fallback(email, *, reason="unavailable", now=None)；rules()；snapshot()、restore(state)、stats()。拒绝时抛 HomeRealmError(code, detail)。

故障与边界：①注册时域名去空白、转小写并去掉末尾点，标签为空或以连字符开头结尾都算非法，抛 ROUTER_BAD_DOMAIN；tenant 或 realm 为空抛 ROUTER_INVALID_REQUEST。②同一域名同一租户重复注册按更新处理，revision 从 1 逐次加一，不新增规则行；不同租户注册同一域名时两条规则都要保留并进入冲突态。③邮箱为空、缺 @、本地部分或域名部分为空抛 ROUTER_INVALID_EMAIL；解析前把邮箱去空白并转小写。④解析取最长后缀匹配，返回 email、domain、matched_domain、tenant、realm、source、conflict、degraded、attempted_realm 与 reason；未命中任何规则时 realm 为 default_realm、source 为 default、matched_domain 为空。⑤子域已单独注册时，父域规则不得覆盖子域。⑥冲突态下不得任选一方，必须回退默认流程并在结果中标注 conflict。⑦解析结果按域名缓存 cache_ttl 秒，缓存命中时 source 为 cache；注册与注销不主动清理已有缓存，只有 TTL 到期、refresh 或身份源健康状态变化才失效。⑧refresh 返回被清掉的缓存条数。⑨身份源被 mark_unavailable 后解析回退到 default_realm、degraded 为真、attempted_realm 保留原身份源；mark_available 后恢复正常。⑩fallback 显式走默认流程，source 为 fallback、degraded 为真并带 reason，仍要填出 matched_domain、tenant 与 attempted_realm。⑪可注册域名总数受 max_domains 限制，新增域名超限抛 ROUTER_CAPACITY，更新已有域名不受限；注销按域名与租户精确删除，不存在返回 False。⑫快照含 version、rules、health、cache、stats 五个顶层键且与活动状态完全脱钩；恢复非法结构抛 ROUTER_SNAPSHOT_INVALID 且不得改动现有数据。stats 返回 registered、resolved、cache_hits、defaults、degraded，其中 defaults 只统计未命中任何规则的解析次数，degraded 统计降级返回的次数，cache_hits 只统计命中缓存的解析次数。

硬约束：同一域名的注册、注销与解析必须串行，最长匹配与冲突判定之间不得插入其它变更；重启或快照恢复后规则、冲突态、健康状态、缓存与计数原样回来，已标记不可用的身份源不得因恢复变回可用，缓存条目也不得跨恢复继续无限期生效。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: home_realm_router
- typeName: HomeRealmRouter
