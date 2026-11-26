# batch50-py-safety-a-05

## 题面

安全组通报一起拖库：某租户的口令表里混进了两代胡椒，用户改完密码第二天又登不上；值班把泄露的那一版直接标停用后，命中它的账号只在下一次登录时被悄悄升级，没有走强制重置。范围是 gsb/batch50-py-safety-a-05 的 password_pepper_ledger.py，类 PasswordPepperLedger，维护租户级胡椒版本与每条口令记录的版本、盐和参数；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：PasswordPepperLedger(*, iterations=60000, max_pending=64, salt_bytes=16)；register_version(version, pepper, now)、current_version()、version_enabled(version)、hash_record(account_id, password, now)、verify(account_id, password, now)、rehash_pending(limit=None, now=None)、disable_version(version, now)、force_reset_required(account_id)、pending_count()、record_for(account_id)、records()、snapshot()、restore(state)、stats()。拒绝一律抛 PepperError(code, detail)。

故障与边界：①版本号只增不减，登记小于或等于当前版本报 PEPPER_VERSION_REGRESSION，version 非正整数或胡椒为空报 PEPPER_INVALID_REQUEST；②新记录一律用当前版本，每条盐随机，摘要按 PBKDF2-HMAC-SHA256 混入胡椒计算，记录里算法名记为 pbkdf2_sha256，并保留迭代次数、盐与摘要；③没有任何版本时写入报 PEPPER_NO_VERSION，当前版本被停用时不得再用于新记录，报 PEPPER_VERSION_DISABLED，停用版本仍然可以被已有记录用来核算口令，account_id 或 password 为空报 PEPPER_INVALID_REQUEST；④校验先用记录所属版本的胡椒核算口令，口令不对一律 invalid，口令对了再看版本状态；⑤记录版本落在当前版与上一版之外归 reset_required，此时 version 仍是记录版本，不得当成口令错误悄悄放过，也不得静默升级；未登记账号返回 unknown 且 version 为 None，record_for 对未登记账号返回 None，records() 按账号升序；⑥上一版校验通过要登记惰性重哈希，同一账号只入队一次，重复登录不再重复入队，VerifyResult 的 rehash_queued 表示本次登录是否新入队；⑦rehash_pending 按队列顺序处理，处理条数受 limit 限制，已经升到当前版的账号直接跳过且不计入重哈希，返回真正完成的条数；⑧待重哈希队列有上限，满了不再入队但登录仍然成功，计入 rehash_deferred；⑨停用版本要返回命中记录条数并标记强制重置，对未知版本报 PEPPER_UNKNOWN_VERSION，重复停用返回 0；⑩长期不登录的账号不能被清理旧版本记录，只能等它自己重哈希或被强制重置；⑪旧版本校验通过但重哈希失败时登录仍应成功并保留旧记录，不能把口令改成未验证状态；⑫停用版本命中的账号必须转强制重置，不能只在下一次登录时静默升级。

硬约束：同一账号的重哈希只能成功一次，多路登录与多处 rehash_pending 并发时不能写出两条互相覆盖的记录，stats 的 rehashed 要与实际升级的账号数一致；快照固定含 version、versions、records、pending、force_reset、stats 六个键，是深拷贝，restore 校验结构，缺键或类型不对报 PEPPER_SNAPSHOT_INVALID 且原状态不被改动，恢复后版本、记录、待重哈希队列与强制重置标记都要继续可用；待重哈希队列与版本登记都是硬上限，超限当场拒绝而不是覆盖旧数据。stats 至少含 versions、hashed、verified、invalid、unknown、reset_required、rehash_queued、rehash_deferred、rehashed、rehash_failed、disabled_versions。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: password_pepper_ledger
- typeName: PasswordPepperLedger
