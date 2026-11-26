# batch50-py-safety-c-02-p2

## 题面

凌晨的备份窗口连着两起投诉：运维用普通账号调 suid 助手做日志轮转，助手把调用方环境里的一串变量原样带进了特权进程，下游子进程加载了不该加载的库；另一台机器上助手启动后还攥着调用方打开的临时文件描述符，任务结束后文件删不掉，事后审计只留下一行启动记录，查不到是谁、带了什么、丢了什么。值班同学一开始怀疑是环境没清干净，可复现脚本换一台机器又正常，说明净化与审计是两套各写各的逻辑，谁也没对谁负责。范围是 gsb/batch50-py-safety-c-02-p2 的 suid_env_sanitizer.py，类 SuidEnvSanitizer，负责在降权之前把环境变量与继承的文件描述符按白名单净化，并在降权后写审计；现在的入口一调用就抛 NotImplementedError，线上等同于闸门没装。

公开接口：SuidEnvSanitizer(*, helper_id, allowed_callers, safe_names=None, audit_fd=3, max_fd=512, max_env_bytes=4096, allow_root_caller=False)；authorize_caller(caller_uid)、sanitize_environment(env)、plan_descriptors(open_fds)、build_launch_plan(caller_uid, target_uid, target_gid, env, open_fds, now)、advance(launch_id, stage)、commit(launch_id, now)、audit_entries()、audit_digest()、verify_audit()、pending_launches()、snapshot()、restore(state)、stats()。环境报告带 kept、dropped、stripped，描述符计划带 keep、close，启动计划带 launch_id、caller_uid、state，回执带 status、stages、audit_seq，审计条目带 seq、launch_id、outcome、code。拒绝一律抛 SuidEnvError(code, detail)。

故障与边界：①变量名必须是字符串且非空、不含等号与 NUL，值必须是字符串且不含 NUL，否则 SUID_INVALID_REQUEST；②只保留 safe_names 里的变量，其余按名丢弃并计数，保留项以名字为键、值原样带回；③危险变量按名字整类剥离：以 LD_ 打头的变量不分大小写、空值与带下划线的变体一并剥离，GCONV_、PYTHON 前缀与 IFS、BASH_ENV、GLIBC_TUNABLES 同样处理；④环境总字节数超过 max_env_bytes 报 SUID_ENV_TOO_LARGE，且不计入任何计数；⑤描述符必须是整数，负数或超过 max_fd 报 SUID_FD_INVALID，重复项去重，0、1、2 必须保留；⑥0、1、2 与显式审计管道之外的继承描述符全部关闭，关闭数量计入审计；关闭动作必须发生在降权之前，降权后再关会因权限不足留下泄漏；降权后残留的描述符不得再被助手或子进程使用；⑦调用方不在 allowed_callers 里报 SUID_CALLER_NOT_ALLOWED，uid 为 0 的调用方默认报 SUID_ROOT_CALLER_REFUSED，除非构造时显式放开；⑧降权目标 uid 不得为 0，否则报 SUID_DROP_REFUSED，不允许"降权"回 root；⑨阶段固定为 sanitize_env、close_fds、audit_pre_drop、drop_privileges、audit_post_drop，advance 只能按序推进并返回刚推进到的阶段名，跳步或重复推进报 SUID_STAGE_ORDER，计划建成时 state 为 planned；⑩commit 只能成功一次，成功时 status 为 launched，重复提交报 SUID_LAUNCH_REPLAY，但每次拒绝都要留审计；⑪被拒绝的启动同样落审计，条目带 outcome 与 code，拒绝记 refused、重放记 replayed、成功记 launched；审计落点只取自构造参数，调用方在环境里塞 AUDIT_LOG、SUID_AUDIT_FD 之类变量不得改变落点；⑫审计序号从 1 连续递增，digest 为条目链的 sha256 小写十六进制，verify_audit 重算链条并给出是否完整。

硬约束：同一助手上的并发启动必须串行，launch_id 唯一、审计序号不重不漏，拒绝与成功都不许丢计数；快照固定为 config、plans、audit、counters、stats 五个键且是深拷贝，restore 结构不符报 SUID_SNAPSHOT_INVALID 且原状态不动，恢复后未提交的计划、审计序号与统计继续可用，重启不能把已提交的计划算回未决。stats 至少含 launches、refused、replayed、env_kept、env_stripped、env_dropped、fds_closed、audit_writes、pending。

验收：`python3 -m pytest -q tests` 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-02-p2
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: suid_env_sanitizer
- typeName: SuidEnvSanitizer
- file: suid_env_sanitizer.py
