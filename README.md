# batch50-py-safety-d-24

## 题面

运维这周给一批测试机批量建号，出了三件事。第一件，脚本只改了 group 里的组成员，gshadow 里的成员名单没同步，机器上 sudo 按 gshadow 判定，新同事进组后仍然没有权限，来回改了四次才对上。第二件，批量脚本跑完提示成功，但另一台机器上还挂着一个已经打开 passwd 的老进程，它继续往旧文件里写快照，第二天同步过去整个文件退回上一版，新账号全没了。第三件，一个脚本失败后自动回滚，可这期间有人手工改过 shadow，回滚把手工改动一起冲掉，客户账号被锁。范围是 gsb/batch50-py-safety-d-24 的 account_db_transaction.py，类名 AccountDbTransaction，负责 passwd、shadow、group、gshadow 四份文件的事务化变更、UID 与 GID 分配、提交后缓存失效与中断恢复。

公开接口：AccountDbTransaction(*, uid_floor=1000, uid_ceiling=60000, gid_floor=1000, gid_ceiling=60000)；load(files: dict) -> dict；files() -> dict；users()；groups()；allocate_uid(name) -> int；allocate_gid(name) -> int；plan(changes) -> ChangePlan；apply(plan_id, *, now) -> CommitResult；rollback(plan_id, *, now) -> int；recover(*, now) -> dict；verify() -> VerifyReport；stats()；snapshot()；restore(state)。拒绝时抛 AccountDbError(code, detail)。变更用 AccountChange(kind, name, fields) 传，kind 取 add_user、delete_user、add_group、join_group、set_shell 之一，fields 里放 shell、home、gid 等可选值。load 返回四份文件各自解析出的条目数，users 按用户名升序返回 name、uid、gid、home、shell，groups 按组名升序返回 name、gid、members 元组。

故障与边界：①四份文件必须按 passwd、shadow、group、gshadow 的固定顺序加锁，ChangePlan.lock_order 如实记录该顺序，files 记录本计划涉及的文件，set_shell 只涉及 passwd，增删用户涉及四份。②plan 只做形状校验，kind 不认识或必填字段缺失抛 ACCOUNTDB_INVALID_CHANGE；占用、重名与一致性问题在 apply 开始时整批判定。③apply 前做一致性校验：重复 UID 抛 ACCOUNTDB_DUPLICATE_UID，重复用户名抛 ACCOUNTDB_DUPLICATE_NAME，passwd 里的 GID 在 group 里找不到抛 ACCOUNTDB_DANGLING_GID，整批拒绝且四份文件一个字节不动；verify 用 duplicate_uids、duplicate_names 列出肇事用户名，dangling_gids 列出悬空用户名，均按用户名升序。④add_user 从 uid_floor 起取最小空闲 UID，跳过已占用与保留号 0、1、2、65534；号段用尽抛 ACCOUNTDB_UID_EXHAUSTED。⑤add_user 同时写 passwd、shadow、同名私有组与 gshadow，shadow 里的口令字段为感叹号锁定位，私有组 GID 与用户 UID 相同，GID 被别的组占用时另取最小空闲 GID。⑥delete_user 一并删除同名私有组，并把该用户从其余组的成员名单里去干净。⑦只改成员关系时 group 与 gshadow 两份成员名单必须同时更新，任何一份没跟上都算失败。⑧写入走同目录临时文件加原子替换，每份被写文件版本加一；替换成功后已持有旧文件句柄的读取方也必须看到新内容，不能读到旧文件。⑨apply 成功返回 CommitResult，带 plan_id、files_written、cache_invalidated、version 与 committed_at；事务版本从 1 起，plan 分配下一个版本号，提交成功后版本推进到该号；提交后按涉及文件数触发 NSS 缓存失效，失效失败只记录不回滚已提交数据。⑩同一计划重复 apply 抛 ACCOUNTDB_PLAN_APPLIED，未知计划抛 ACCOUNTDB_PLAN_UNKNOWN；rollback 恢复提交前的相关文件与版本并返回恢复的文件数。⑪回滚前比对当前文件与提交后的映像，发现被外部改过就抛 ACCOUNTDB_ROLLBACK_CONFLICT，保留当前状态而不是覆盖。⑫进程中断后 recover 凭事务日志回到最后一个一致状态，返回本轮恢复条数；快照保存文件内容、版本水位、计划与计数，非法快照抛 ACCOUNTDB_SNAPSHOT_INVALID；stats 给出 users、groups、plans、commits、rollbacks、cache_invalidations、recovered 七项。

硬约束：同一用户的并发变更按用户加锁串行，不同用户之间并行，四份文件的锁获取顺序全局固定以避免死锁；跨文件变更要么全成要么全不成，中途失败不得留下半套；快照与活动状态完全脱钩，恢复后文件、版本、计划与计数原样回来。验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: account_db_transaction
- typeName: AccountDbTransaction
