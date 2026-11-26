# batch50-py-safety-d-22

## 题面

权限中心这周的工单集中在三件事上。一次是运维把发行版自带的放行规则用管理员规则收紧之后，同一个人既能匹配到管理员写的拒绝，又能匹配到发行版默认的放行，实际执行时结果随重启飘，有时放行有时拒绝；一次是安全组热加载了新规则，已经弹给用户的认证框在用户输完口令确认后仍然按旧规则给了授权，热加载等于没生效；还有一次是用户在认证过程中注销了登录会话，认证框还挂着，确认之后照样拿到授权，第二天换个人登录直接继承了这份授权。安全组复核时又发现，同一个人连点两次授权，第二次直接命中前一次的旧裁决，规则当天已经改过，结论却还是旧的。四条都被审计判为授权链断裂。范围是 gsb/batch50-py-safety-d-22 的 polkit_rule_engine.py，类名 PolkitRuleEngine，负责动作登记、规则分层求值、认证挑战与授权会话。

公开接口：PolkitRuleEngine(*, max_attempts=3, challenge_ttl=300, grant_ttl=600, cooldown_seconds=60)；register_action(action, *, description="")；load_rules(rules, *, now) -> int；evaluate(user, action, *, groups=(), now) -> Decision；challenge(user, action, *, groups=(), now) -> Challenge；complete(challenge_id, *, proof_ok, now) -> Authorization；authorize(user, action, *, groups=(), now) -> Authorization；revoke(user, action) -> int；end_session(user) -> int；active_challenges()；stats()；snapshot()；restore(state)。拒绝时抛 PolicyError(code, detail)。规则用 Rule(source, action, subject, subject_kind, result) 传，source 只认 admin 与 vendor，subject_kind 只认 user 与 group，result 取 yes、no、auth_self、auth_admin 之一。

故障与边界：①未登记动作求值抛 POLICY_UNKNOWN_ACTION，未知 source、subject_kind、result 抛 POLICY_INVALID_RULE。②管理员层覆盖发行版层，同层内按传入顺序首个匹配生效；都不匹配按 no 处理且 Decision.source 为 None。③组规则按主体所在组匹配，主体不在该组时不命中。④yes 直接授权且不再发起挑战；no 调 authorize 抛 POLICY_DENIED 并让 denied 加一；auth_self 与 auth_admin 调 authorize 抛 POLICY_AUTH_REQUIRED，必须先走 challenge。⑤挑战一次一用，expires_at 等于发起时刻加 challenge_ttl，到期即失效，complete 抛 POLICY_CHALLENGE_EXPIRED。⑥同一挑战重复 complete 幂等，返回同一份授权，completed 只加一次。⑦proof_ok 为假抛 POLICY_BAD_CREDENTIALS 并累加尝试次数；累计到 max_attempts 的那一次失败直接抛 POLICY_COOLDOWN，该主体对该动作进入冷却，冷却期内 challenge 与 authorize 都抛 POLICY_COOLDOWN。⑧授权到期时间等于授予时刻加 grant_ttl，到期后 authorize 重新求值；revoke 撤销该主体该动作的活动授权并返回条数，revoked 计数加一。⑨主体在挑战期间注销登录，end_session 要把该主体名下未完成挑战与活动授权一并作废。⑩规则热加载整体换表并把版本号加一，挑战在热加载之后完成时按发起时记录的规则版本判定。⑪同一主体同一动作在同一规则版本内重复求值命中缓存，Decision.cached 为 True；换版本后缓存作废，下一次求值 cached 为 False。⑫同一主体属于多个组且规则分别给 yes 与 no 时，按规则表顺序裁决，不按组优先级；快照保存规则版本与未完成挑战，非法快照抛 POLICY_SNAPSHOT_INVALID 且不改现状。stats 给出 actions、rules_version、evaluations、challenges、completed、denied、revoked、cache_hits 八项。

硬约束：规则求值与热加载用同一把读写锁互斥，求值过程中不得看到半张规则表；authorize 与 complete 按会话串行，同一挑战只发一份授权；授权缓存按规则版本与主体失效，换版本后旧裁决不得被复用。验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: polkit_rule_engine
- typeName: PolkitRuleEngine
