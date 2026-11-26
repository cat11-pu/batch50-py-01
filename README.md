# batch50-py-safety-c-04-p2

## 题面

审计季的权限复核翻出三件事。一件是备份线程以 root 身份跑完之后没回落，同进程后续写出的归档文件 uid 全是 0，交接时被当成异常提权；一件是某次写入失败后线程停在 uid 已改、gid 没改的中间态，文件属主和属组对不上，权限矩阵全乱；还有一件是退出时只清了最后一层，前面压进去的三层身份一直悬着，进程在收尾阶段仍然拿着不该有的权限跑了二十分钟，日志里连一条切换记录都没有。范围是 gsb/batch50-py-safety-c-04-p2 的 fsuid_switch_guard.py，类 FsuidSwitchGuard，负责线程级身份切换的作用域、嵌套计数、异常与超时回落、审计留痕。

公开接口：FsuidSwitchGuard(*, baseline=(1000, 1000), privileged=False, max_depth=8)；push_scope(target, *, reason="", timeout=None, now=None) 返回 ScopeHandle(worker, depth, target, deadline)；pop_scope(handle) 返回恢复后的身份元组；current_identity()；force_baseline(*, reason="manual")；tick(now)；scope_depth()；audit_trail(*, limit=None) 返回 AuditEntry(seq, worker, action, identity_from, identity_to, reason, ok)；set_baseline(uid, gid)；inject_fault(point, *, times=1)；snapshot()、restore(state)、stats()。所有拒绝统一抛 GuardError(code, detail)。

故障与边界：①target 必须是两个非负整数组成的二元组，布尔、负数、三元组、字符串、None 一律 IDENTITY_INVALID；timeout 与 now 必须同时给出且为正整数，否则 SCOPE_INVALID；②非特权守卫不得切到 uid 比基身份更小的身份，报 ELEVATION_DENIED，只有构造时 privileged=True 才允许降到 0，切到 uid 更大的身份属于降权，放行；③嵌套超过 max_depth 报 DEPTH_EXCEEDED，栈与当前身份保持原样；④pop 必须按压入顺序逆序，深度或目标对不上报 SCOPE_OUT_OF_ORDER，跨线程拿别处的句柄来 pop 报 SCOPE_FOREIGN；⑤作用域内再次切到相同身份需要计数，pop 一次不能提前恢复基身份；⑥切换过程中第二步失败时第一步必须被撤销，不得留下半切换状态，注入 gid 步骤失败后 push 要抛 SCOPE_ROLLED_BACK，当前身份与深度都不变，审计里留一条 rolled_back 失败记录；⑦force_baseline 清空当前线程全部作用域回到基身份，栈非空才算一次 forced_returns，栈本来就空时只返回基身份，不计数也不追加审计；⑧tick(now) 让到期作用域整体强制回落并返回本次回落的作用域个数，同时计入 expired_scopes，当前身份回到基身份；⑨set_baseline 只在没有活动作用域时允许，否则报 GUARD_BUSY，成功之后 current_identity 立刻变成新基身份，后续提权判断按新基身份算；⑩pop 返回恢复后的身份元组，逐层退回上一层目标，最后一层回到基身份；⑪审计序号自 1 全局递增，动作只用 push、pop、denied、force_baseline、rolled_back、set_baseline 这几个取值，每条记录动作、前后身份、原因与是否成功，limit 取最近若干条，被拒绝的动作同样要留痕；⑫snapshot 返回 schema、baseline、workers、seq、stats 五个键且深拷贝，restore 缺键或类型不符报 SNAPSHOT_INVALID 且原状态不变。

硬约束：线程隔离，一个线程的切换、回落、到期都不得影响另一个线程的当前身份与作用域深度，身份变更与审计追加必须在锁内完成，审计序号不重不跳；异常与超时路径上必须回到基身份，任何失败都不许留下 uid 改了 gid 没改的半切换，回落动作只能发生一次，重复回落不得重复计数。stats 固定返回 pushes、pops、denied、forced_returns、expired_scopes、depth_peak、faults_injected 七个键。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；线程隔离与超时回落自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-04-p2
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: fsuid_switch_guard
- typeName: FsuidSwitchGuard
- file: fsuid_switch_guard.py
