# batch50-py-safety-c-08-p2

## 题面

包管理平台这周出了三次生产事故：一次是两个运维同时给同一台机器装包，前一个事务还没提交完，后一个就写进去了，最后谁也不知道机器上到底是哪个版本；一次是升级做到一半机器断电，重起来之后事务日志里只有意图没有结论，工具直接把最后一步重放了一遍，把已经升级好的包又装了一次；还有一次事务其实已经提交完成，值守的人误触了中止，回滚把线上依赖全拆了。范围是 gsb/batch50-py-safety-c-08-p2 下的 pkg_transaction_ledger.py，类 PkgTransactionLedger，负责全局锁、分步意图日志、提交推进与中断后的续做或回滚判定。

公开接口：PkgTransactionLedger(*, lock_lease_ms=30000)；seed_installed(package, version)、installed(package=None)；begin(owner, requests, *, now, lease_ms=None) 返回事务号；stage(txid, *, now) 返回 StepRecord；commit(txid, *, now, limit=None) 返回 state、applied、total；abort(txid, *, now) 返回回滚步数；recover(txid, *, now) 返回 outcome、reverted、applied；holders()；status(txid)；journal(txid)；snapshot、restore、stats。requests 每项是带 op、package、version 的字典，op 取 install、remove、upgrade；版本号只接受点分的数字段。拒绝时抛 PkgError(code, detail)。

故障与边界：①owner 为空、requests 为空、同一事务重复包、未知 op、版本号格式非法报 PKG_INVALID_REQUEST；②install 已装、upgrade 未装或目标不高于当前、remove 未装或指定版本与当前不符，分别报 PKG_ALREADY_INSTALLED、PKG_NOT_INSTALLED、PKG_VERSION_CONFLICT；③全局锁同一时刻只允许一个事务，锁未到期时新事务报 PKG_LOCK_HELD 并在 detail 里给出持有者、事务号与到期时刻；到期后新事务接管，旧事务置为 abandoned 并计入 seized；④计划步骤按请求顺序编号，初始 pending；stage 只写队首未写意图的步骤，队首已有意图尚未执行时再调报 PKG_STEP_STATE；⑤commit 按 seq 顺序先落意图再执行，全部执行完才写提交标记并释放锁，返回的 applied 为累计已执行步数；⑥commit 带 limit 时只推进指定步数，未完成时保持 applying 并继续持锁；⑦abort 逆序回滚已执行步骤：install 删除包、upgrade 与 remove 还原旧版本，未执行步骤保持 pending；⑧对已提交事务调用 abort 必须报 PKG_IRREVERSIBLE，且不得改动任何步骤记录；⑨recover 对 applying 且尚有未执行步骤的事务回滚并返回 rolled_back；完全没执行过的事务置 abandoned 返回 discarded；已提交、已回滚或已放弃的事务报 PKG_TX_CLOSED；⑩中断发生在最后一步已执行、提交标记尚未写入时，recover 必须判定为已完成、补写标记且不得重放最后一步；⑪快照含 version、installed、transactions、steps、lock、counters、next_tx，lock 与 holders() 同构，快照与内部状态不共享，restore 结构非法报 PKG_SNAPSHOT_INVALID 且不改现有数据；⑫未知事务的查询与推进报 PKG_UNKNOWN_TRANSACTION。

硬约束：并发 begin 只允许一个拿到全局锁，其余必须拿到 PKG_LOCK_HELD，不得出现两个事务同时推进；快照恢复后锁持有者、步骤状态与已执行计数必须一致，续做时已执行步骤不得二次执行。只做本地实现，不得改测试、跳过或按固定输入写死；并发与重启自行验证。验收运行 python3 -m pytest -q tests，15 条全部通过。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: pkg_transaction_ledger
- typeName: PkgTransactionLedger
