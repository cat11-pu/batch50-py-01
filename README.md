# batch50-py-safety-d-19

## 题面

检测规则库这周两次把线上扫描引擎拖死：一条规则在恶意样本上回溯了几十秒，把整个队列堵住；另一条静态看着很简单，基准一跑就超时，却因为评分不高被放进了规则集；还有人手工批准的规则到期后没人续，一直带着旧批准在跑。范围是 gsb/batch50-py-safety-d-19 的 regex_dos_guard.py，类 RegexDosGuard，负责规则登记、复杂度评分、基准、隔离与批准。

公开接口：RegexDosGuard(*, max_rules=200, budget_seconds=0.05, max_samples=8, clock=None, executor=None)；register(pattern, *, flags=0)、analyze(pattern, *, flags=0)、benchmark(rule_id, samples, *, budget_seconds=None)、quarantine(rule_id, reason)、approve(rule_id, *, approved_by, ttl_seconds, now=None)、load_ruleset()、effective_rules()、expire_approvals(now=None)、stats()、snapshot()、restore(state)；异常统一抛 RegexSafetyError(code, detail)。

故障与边界：①规则号形如 R-0001 顺序递增，指纹取 sha256(模式 + 0x1f 分隔符 + 十进制标志位) 的前 16 位十六进制，同指纹重复登记只返回原记录并累加去重数；②静态评分三段：被量词修饰的括号组内部又含量词记 NESTED_QUANTIFIER 70 分，交替分支相等或互为前缀记 OVERLAPPING_ALTERNATION 40 分，连续出现两个及以上 .* 或 .+ 记 REPEATED_DOT_STAR 35 分；③总分封顶 100，70 分及以上判 high，40 到 69 判 medium，其余 low，命中项去重后按字母序放进 findings；④空模式或非字符串抛 REGEX_INVALID_REQUEST，规则数超过 max_rules 抛 REGEX_CAPACITY_EXCEEDED；⑤基准调用注入的 executor(pattern, sample) 取回毫秒数，结果给 rule_id、samples、total_ms、sample_count、status，合计超预算时 status 记 exceeded；⑥样本条数超过 max_samples 抛 REGEX_SAMPLE_LIMIT，样本为空抛 REGEX_INVALID_REQUEST；⑦载入规则集只收 low 与 medium，high 规则默认跳过，人工批准过的 high 规则可以载入；⑧批准必须带正数 ttl，到期时间等于批准时间加 ttl，ttl 非正抛 REGEX_APPROVAL_TTL_INVALID；⑨批准到期后 expire_approvals 把规则退回隔离并返回条数；⑩隔离与批准遇到未知规则号抛 REGEX_RULE_UNKNOWN，编译失败与基准超时分别记编译失败数、超时数，两种原因不能混记；⑪同一正则在开启不同标志位时回溯行为不同，指纹必须把标志位算进去，不能只按模式文本去重；⑫静态评分低但基准超时的规则仍然要隔离；批准到期时规则正在被使用，不能中途卸载，只能在下一次载入时生效并记录宽限。

load_ruleset 返回 loaded、excluded、compile_failures 三个元组，按登记顺序排列；effective_rules 按当前状态实时给出可载入的规则号，与最近一次载入结果一致。stats 返回 registered、deduped、quarantined、approved、approvals_expired、loaded、compile_failures、timeouts 八个计数。基准样本要包含对抗性构造，比如重复字符、嵌套括号与超长前缀；同一规则重复基准只累加次数与样本数，不覆盖首次评分与隔离原因。

硬约束：register 与 approve 的状态迁移共用一把 threading.RLock，评分、裁决与批准到期时间必须在一次迁移内写完，并发登记同一模式只能产生一条规则；snapshot 返回 version、rules、counters、loaded 四个键且为深拷贝，restore 遇缺键或类型不符抛 REGEX_SNAPSHOT_INVALID 且不改动现有规则与计数。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: regex_dos_guard
- typeName: RegexDosGuard
- file: regex_dos_guard.py
