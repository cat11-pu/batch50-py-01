# batch50-py-safety-a-06

## 题面

身份核验工单这周连着出岔子：有申请人换账号拿同一张证件反复开单，两条工单各自走完流程，最后都判了通过，运营事后才发现是同一份证明材料；审核员点开单子被电话叫走，租约到期后系统把单子改派给别人，他回来补的那条结论居然覆盖了接手人的判断；还有人把活体检测连刷九次才被拦住，前三次之后的冷却形同虚设；更麻烦的是服务重启一次，待复核队列的顺序和租约剩余时间全对不上，值班只能人工重排。范围是 gsb/batch50-py-safety-a-06 的 proofing_case_ledger.py，类 ProofingCaseLedger，负责申请人工单、证件与活体尝试额度、复核租约与结论落定。

公开接口：ProofingCaseLedger(*, attempt_limit=3, cooldown_seconds=600, lease_seconds=300)；open(applicant, doc_digest)、attempt(case_id, kind, material, result)、budget(case_id, kind)、assign(case_id, reviewer)、decide(case_id, reviewer, decision, reason)、reclaim(case_id)、view(case_id)、queue()、snapshot()、restore(state)、stats()；时间参数统一 now，取整秒。拒绝一律抛 ProofingError(code, detail)。open、view、decide 返回 CaseRecord，字段含 case_id、state、ready_at、decision、decided_by、decided_at；attempt 返回 AttemptRecord，字段含 attempt_id、window；assign、reclaim 返回 LeaseRecord，字段含 reviewer、granted_at、expires_at、generation，每条记录都是冻结对象。

故障与边界：①字符串参数一律去空白后判定，空申请人或空摘要抛 PROOF_INVALID，kind 只收 document 与 liveness，result 只收 pass 与 fail；②同一申请人未定案时重复开单幂等合并，沿用原 case_id 并计 merged，不新开计时；③case_id 从 case-1 递增，新单 state 为 collecting，状态只能依次走 collecting、ready、in_review、decided；④失败尝试按 kind 各自窗口计额度，默认 3 次，用尽后抛 PROOF_BUDGET，冷却 cooldown_seconds 满后窗口归零，冷却期内 budget 返回 0，每次尝试的 window 记该 kind 当前窗口内第几次，从 1 起、冷却后重计；⑤pass 不占额度，document 与 liveness 都 pass 后转 ready 并记 ready_at 入队；⑥queue 只列待复核单，按 ready_at 升序、同刻按 case_id 升序，已派单与已定案的出队；⑦assign 只对 ready 生效否则 PROOF_STATE，租约未到期再派抛 PROOF_LEASE，generation 自 1 递增，expires_at 为派单时刻加 lease_seconds；⑧decide 只收 approve 与 reject，理由去空白后不得为空，否则 PROOF_INVALID，非当前租约持有人交结论抛 PROOF_LEASE；⑨结论一经作出不可改写，重复 decide 抛 PROOF_FINAL 且记录不动，未知单号抛 PROOF_UNKNOWN；⑩reclaim 只在到期时刻含等于时回收并计 reclaimed，未到期返回 None，回收后回到 ready 重新入队；⑪另外两条必须处理：不同申请人提交同一证件号要标记重复申请，不能各自独立通过，租约过期后原审核员再提交结论必须被拒绝，不能覆盖接手人的决定。

硬约束：开单、录尝试、派单、定案与快照全程持锁，同一单子被多路并发提交时成功条数不得超过剩余额度，attempts 计数不得丢，统计在并发下不得错账；快照是 cases、attempts、leases、counters 的深拷贝，恢复后租约剩余时间、队列顺序与额度窗口都按快照延续，结构非法抛 PROOF_SNAPSHOT 且原状态不变。stats 固定返回 opened、merged、attempts、refused、assigned、reclaimed、decided。

验收：`python3 -m pytest -q tests` 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: proofing_case_ledger
- typeName: ProofingCaseLedger
- file: proofing_case_ledger.py
