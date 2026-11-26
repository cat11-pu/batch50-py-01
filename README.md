# batch50-py-safety-c-14

## 题面

漏洞赏金项目在季度结算时被审计挑出三处对不上的地方：两份不同研究员提交的报告其实是同一个根因，评审各自独立走完流程，同一份奖金被发了两次；一位评审临时离席，报告在他的名下锁了两天，别人既领不走也看不到进度；还有一个高优项目的额度已经用完，队列却一直停在待发奖状态，后面所有报告都被堵住。更糟的是一次评级复核把高危改成了中危，却没有任何留痕，研究员申诉时拿不出依据。范围是 gsb/batch50-py-safety-c-14 下的 bounty_triage_queue.py，类名 BountyTriageQueue：负责报告入队、按目标与根因指纹查重、带租约的评审领取、裁决与评级复核、项目额度台账以及报告关闭。

公开接口：BountyTriageQueue(*, lease_seconds=900, project_budget=10000)；submit(report_id, *, target, fingerprint, reporter, severity, now)；dedupe_against(target, fingerprint)；claim_review(report_id, *, reviewer, now)；record_verdict(report_id, *, reviewer, lease_id, verdict, severity, now)；award(report_id, *, amount, now)；adjust_severity(report_id, *, new_severity, actor, now)；close(report_id, *, reason, now)；queue(*, state=None)；ledger()；snapshot()；restore(state)；stats()。拒绝时抛 BountyError(code, detail)，报告与租约分别用只读对象 BountyReport、ReviewLease 返回。

故障与边界：①submit 校验 report_id、target、fingerprint、reporter 为非空字符串，severity 只能取 low、medium、high、critical，否则抛 BOUNTY_BAD_REQUEST 或 BOUNTY_BAD_SEVERITY；重复 report_id 抛 BOUNTY_DUPLICATE_REPORT；报告字段含 report_id、target、fingerprint、reporter、severity、state、duplicate_of、verdict、award_amount、submitted_at、closed_at。②同一 target 与 fingerprint 已有报告时，新报告仍要入队并保留，状态标为 duplicate、duplicate_of 指向最早匹配的报告，不进入评审队列；与已关闭报告重复时同样保留并标记，但不得重复计奖或改写旧报告。③dedupe_against 返回同 target、fingerprint 的报告标识元组，按升序包含各种状态，查询本身不修改任何数据。④claim_review 只对 queued 报告生效，其他状态抛 BOUNTY_BAD_STATE；存在未到期租约时抛 BOUNTY_LEASE_HELD，租约带 lease_id、reviewer、expires_at，到期后可由他人重新领取，旧租约随之失效。⑤同一报告被并发评审时只能有一份租约生效，裁决以先落库的有效租约为准，另一份租约提交裁决必须收到 BOUNTY_LEASE_INVALID，不得覆盖已生效结论。⑥record_verdict 需要匹配当前有效租约，verdict 只能取 valid、invalid、duplicate，否则抛 BOUNTY_BAD_VERDICT；成功后状态转 triaged、释放租约，severity 采用本次裁决值。⑦award 只对 triaged 且 verdict 为 valid 的报告生效，否则抛 BOUNTY_NOT_AWARDABLE；amount 必须为正整数，否则抛 BOUNTY_BAD_AMOUNT。⑧奖金从项目额度扣减，额度足够时状态 awarded、ledger 追加 report_id、amount、at、severity 并返回 report_id、state、awarded、amount 与 remaining；额度不足时降级为 acknowledged、awarded 为假、金额为 0，不得阻塞后续报告，也不得出现负余额。⑨adjust_severity 只允许上调且仅一次，留痕并返回 old、new、actor、at；下调或持平抛 BOUNTY_SEVERITY_DOWNGRADE，第二次调整抛 BOUNTY_REVIEW_LOCKED。⑩close 把报告转 closed、记录 closed_at 并释放租约；未知报告抛 BOUNTY_UNKNOWN_REPORT，已关闭再关抛 BOUNTY_BAD_STATE；queue 可按状态过滤并按 report_id 升序，ledger 按入账顺序返回。⑪快照包含版本、报告、租约、台账、评级留痕、项目额度与计数，恢复非法结构抛 BOUNTY_SNAPSHOT_INVALID 且不改动现有数据。⑫重启后额度余额、租约到期时间、台账与报告状态原样恢复，已发奖金不得因为恢复而重复入账；stats 返回 submitted、duplicates、verdicts、awards、acknowledged、adjusted 六项。

硬约束：submit、claim_review、裁决与发奖必须串行，额度扣减与台账写入之间不得插入其它发奖，并发领取同一报告只能产生一份有效租约；快照与恢复必须原子，恢复失败不得留下半更新的台账或额度。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: bounty_triage_queue
- typeName: BountyTriageQueue
