# batch50-py-safety-d-16

## 题面

权限矩阵这轮又挖出三条越权，都是人工点出来的：同一批接口换个低权角色就能读到别人的订单；自动化脚本跑到一半被目标封号还在继续打；进程重启后进度全丢，只能从头再来一遍。范围是 gsb/batch50-py-safety-d-16 的 authz_matrix_prober.py，类 AuthzMatrixProber，负责把端点与角色拼成探测矩阵，按分片执行、逐条落盘进度并支持断点续跑。

公开接口：AuthzMatrixProber(*, executor=None, max_entries=500, rate_per_minute=60, clock=None)；register_endpoint(method, path, *, domain, resource_kind="own", write=False)、register_role(name, account_id, *, write_allowed=False)、build_matrix()、run_shard(shard_index, shard_count, *, now=None)、pause(reason)、resume(now=None)、progress()、report()、blocked_roles()、set_rate_budget(domain, per_minute)、snapshot()、restore(state)；拒绝一律抛 MatrixError(code, detail)。

故障与边界：①矩阵按端点×角色笛卡尔积展开，端点按登记顺序、端点内按角色登记顺序，条目序号从 0 连续递增；②条目指纹取「大写方法 + 空格 + 路径 + 空格 + 角色名」的 sha256 前 16 位十六进制，同一端点重复登记只留一条并累加去重数；③请求标记 marker 形如 MK-<指纹前 8 位>-<四位序号>，全局不重复；④写接口对只读角色预期 deny，其余预期 allow，预期写进条目；⑤分片按条目序号对 shard_count 取模，已完成的条目重跑不再执行；⑥暂停后 run_shard 抛 MATRIX_PAUSED，resume 返回 status 与 completed；⑦按目标域每分钟配额计费，超限只暂停并把 paused_reason 记为 rate_budget，已执行结果保留、剩余条目仍 pending，不抛异常；⑧矩阵规模超 max_entries 时在 build_matrix 抛 MATRIX_CAPACITY_EXCEEDED；⑨空方法、空路径、空角色名抛 MATRIX_INVALID_REQUEST，shard_count 小于 1 或 shard_index 越界抛 MATRIX_SHARD_INVALID；⑩401/403 记 denied，2xx 且响应 resource_owner 与角色账号不同记 exceeded，2xx 且相同记 granted，其余状态码记 review；⑪角色对不存在的资源拿到 404 时，必须拿同端点的存在资源做对照后再定性，不能直接算拒绝；⑫角色权限在探测期间被改动，一律按构建矩阵时的角色快照判定；⑬同一账号瞬时并发过高被风控封禁后，剩余条目记 invalid，不能算越权。

执行器由构造参数注入，签名 executor(entry) 返回 (status_code, body)，body 只读 resource_owner 与 summary 两个键，summary 超过 120 字要截断；没有注入执行器时 run_shard 抛 MATRIX_INVALID_REQUEST。标记随请求头下发，同一个 marker 在审计日志里要能反查到条目指纹；结果按条目序号追加保存，不因分片执行顺序不同而改变顺序。blocked_roles() 返回被阻塞的角色名并按字母序排列。

run_shard 返回 executed、status 与 results（本轮新产生的 ProbeResult，字段 index、fingerprint、verdict、status_code、evidence）；report() 返回 total、executed、deduped、verdicts（denied/granted/exceeded/review/invalid 五个计数）与 blocked_roles；progress() 返回 status、completed、paused_reason 与 shards（分片号到已完成数的映射）。

硬约束：run_shard 与 resume 用 threading.Lock 按目标域隔离，同一域的进度更新与配额扣减必须原子，多线程并发跑不同分片不得重复执行同一条目；snapshot 返回 version、endpoints、roles、entries、results、deduped、shards 七个键且为深拷贝，restore 遇缺键或类型不符抛 MATRIX_SNAPSHOT_INVALID 且不改动现有状态。证据只保留状态码与响应摘要，不落响应正文。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: authz_matrix_prober
- typeName: AuthzMatrixProber
- file: authz_matrix_prober.py
