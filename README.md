# batch50-py-safety-c-05

## 题面

运维值班这周处理了四起定时任务事故：一台机器上的备份任务在夏令时切换那一小时跑了两遍，第二遍把增量目录覆盖成空；另一台机器被系统时间回拨后，同一分钟的清理任务又触发一次，把还没归档的日志删了；还有人把自己的任务写进别人的 crontab，代理只校验文件存在就放行；一个任务卡住没退出，后续实例照样排队启动，用户配额和并发配额都没起作用。值班同事还发现，代理把宿主机上的 IFS、LD_PRELOAD 原样传给了任务，同一个脚本在代理里跑出来的行为和手工执行完全不一样。范围是 gsb/batch50-py-safety-c-05 的 cron_job_warden.py，类 CronJobWarden，负责任务登记、配额、运行准入、环境净化与台账回收。

公开接口：CronJobWarden(*, work_root="/var/tmp/jobs", max_jobs_per_user=10, max_concurrent_per_user=4, max_runtime=3600)、register(job_id, *, user, command, schedule, crontab_path, crontab_owner=None, max_concurrent=1, now=None)、remove(job_id)、disable(job_id)、enable(job_id)、lock_user(user)、unlock_user(user)、authorize_run(job_id, *, now=None, scheduled_for=None)、acquire_slot(run_id, *, now=None)、finish(run_id, *, now=None, exit_code=0)、reap(*, now=None, max_runtime=None)、env_for(job_id, environ)、workdir_for(job_id)、render_crontab(user)、write_crontab(user, path)、snapshot()、restore(state)、status()、stats()。run_id 由模块内部生成且唯一，register 传进来的 now 记入 registered_at，register 返回 JobRecord(job_id, user, command, schedule, crontab_path, max_concurrent, enabled, registered_at)，authorize_run、acquire_slot 与 finish 返回 RunInstance(run_id, job_id, user, state, slot, started_at, finished_at, exit_code)，拒绝统一抛 CronWardenError(code)。

故障与边界：①register 的 job_id 重复报 CRON_JOB_DUPLICATE，crontab_owner 与 user 不一致报 CRON_OWNERSHIP_MISMATCH，同一用户登记数超过 max_jobs_per_user 报 CRON_JOB_QUOTA_EXCEEDED；②schedule 只接受 every:秒（60 到 86400）与 daily:HH:MM（00:00 到 23:59），其余报 CRON_SCHEDULE_INVALID；③任务禁用后 authorize_run 报 CRON_JOB_DISABLED，重新启用后恢复，disable 与 enable 返回本次是否真的改了状态；④acquire_slot 按任务 max_concurrent 发槽，槽位占满报 CRON_CONCURRENCY_LIMIT，同一 run 重复 acquire 幂等，finish 释放槽位；⑤finish 对已结束实例幂等，重复调用不改 exit_code、不重复计数；⑥未知任务报 CRON_JOB_UNKNOWN，未知 run 报 CRON_RUN_UNKNOWN；⑦reap 把运行时长达到 max_runtime 秒的实例标为 reaped、收回槽位并返回条数，没到时长不动，时长按 started_at 与 now 的秒差算而不是看标记位；⑧restore 之后台账里的在跑实例仍可被 reap 回收，恢复快照不能把已回收实例重新算成在跑；⑨env_for 只保留 PATH、HOME、LANG、LOGNAME，强制 SHELL=/bin/sh、PWD 为 workdir_for(job)，其余变量（IFS、LD_PRELOAD、BASH_ENV、PYTHONPATH 等）一个都不能带进去，也不得改动传入的字典，workdir_for 返回 work_root 下按用户分目录的路径；⑩render_crontab 按 job_id 升序、每行"<schedule> <command>"、行末换行、禁用任务不出现，write_crontab 原子替换目标文件并返回写入字节数；⑪crontab 文件被替换成指向其他用户文件的符号链接时必须拒绝写入；⑫系统时间回拨后同一时间点不得重复触发同一任务，任务运行中其所属用户被锁定后，后续实例必须拒绝而不是继续排队。

硬约束：登记、配额、准入、发槽与回收在同一把锁内完成，同一任务并发准入不得超发；登记表、台账与计数器可快照可恢复，恢复后计数与在跑实例一致，重启后未结束实例按超时回收。status 固定给出 jobs、enabled、disabled、queued、running、finished、reaped、users、locked_users，stats 固定给出 registered、removed、disabled、enabled、runs_authorized、slots_acquired、runs_finished、runs_reaped。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发准入与重启回收自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-05
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: cron_job_warden
- typeName: CronJobWarden
- topic: 定时任务授权治理：用户配额、运行环境净化与重叠执行抑制
