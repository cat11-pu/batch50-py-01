# batch50-py-safety-c-30

## 题面

安全合规这季度要求全租户上多因子，推行组按百分比分批放开，结果第一天就乱了：同一批用户有的被要求注册、有的没被要求，第二天再登录结论又反了；分阶段推进时有人明明还在宽限期却被立刻拦下，也有人宽限拖了一个月；临时豁免的出差人员回国后仍能绕过强制，客服只能手工改配置；阶段从 100% 退回 10% 后，已经强制过的用户突然可以不做多因子，审计直接判不合规。范围是 gsb/batch50-py-safety-c-30 下的 mfa_rollout_governor.py，类名 MfaRolloutGovernor，负责按租户阶段与百分比做稳定分桶、计算宽限梯度、管理豁免与统计推行结果。

公开接口：MfaRolloutGovernor(*, base_grace_days=7)；set_stage(tenant, *, stage, percent, now=None) 返回 RolloutStage（含 tenant、stage、percent、updated_at）；bucket_of(tenant, user_id)；evaluate(tenant, user_id, *, now=None) 返回 MfaDecision（含 tenant、user_id、bucket、stage、percent、cohort、state、requires_mfa、grace_until、exemption_until）；grant_grace(tenant, user_id, *, days, now=None)；exempt(tenant, user_id, *, until, reason, now=None)；revoke_exemption(tenant, user_id)；mark_enrolled(tenant, user_id, *, now=None)；report(tenant, *, now=None)；snapshot()、restore(state)、stats()。拒绝时抛 MfaRolloutError(code, detail)。

故障与边界：①set_stage 的 stage 只接受 0 到 3，percent 只接受 0 到 100 的整数，越界分别抛 MFA_BAD_STAGE 与 MFA_BAD_PERCENT；tenant 为空抛 MFA_INVALID_REQUEST。②bucket_of 只由 tenant 与 user_id 决定，跨进程、跨实例稳定，取值 0 到 99；百分比判定为 bucket 小于 percent 时进入分桶。③未进入分桶且从未被强制的用户 state 为 not_required、requires_mfa 为假。④首次进入分桶的用户进入宽限，宽限天数按 max(1, base_grace_days * (100 - percent) // 100) 计算，在首次进入时固定，之后改百分比不重算；state 为 grace、requires_mfa 为假、grace_until 为截止时间。⑤now 达到或超过 grace_until 时转为 enforced、requires_mfa 为真，grace_until 保留原截止时间；强制状态一旦产生不得撤销，阶段回退或百分比下调后该用户仍为 enforced，cohort 字段只反映当前百分比判定。⑥宽限到期仍未注册的用户在下次评估时直接强制，不得重新给宽限。⑦用户完成注册后应立即脱离宽限，不必等阶段推进，state 为 satisfied。⑧grant_grace 只对已进入分桶且未强制、未注册的用户生效，days 必须为正整数，从当前 grace_until 继续加天数，已过期则从 now 起算，返回 user_id 与 grace_until；不满足状态抛 MFA_STATE_INVALID。⑨exempt 的 until 必须是晚于 now 的合法时间、reason 非空，否则抛 MFA_INVALID_REQUEST，成功返回 user_id、until 与 reason；now 早于 until 时 state 为 exempt、requires_mfa 为假。⑩豁免到期当天就要重新评估并纳入强制，不能拖到次日；revoke_exemption 删除成功返回 True，不存在返回 False，之后按正常分桶重新计算。⑪report 按当前时间统计该租户曾评估、已豁免与已注册用户的 not_required、grace、enforced、exempt、satisfied 五类人数，只读不改变评估计数；stats 返回 evaluations、grace_started、enforced、exemptions_granted、stage_changes，enforced 只在首次转入强制时加一。⑫快照含 version、stages、users、grace、enrollments、exemptions、forced、stats 八个顶层键且与活动状态完全脱钩；恢复非法结构抛 MFA_SNAPSHOT_INVALID 且不得改动现有数据。

硬约束：同一租户的阶段变更、同一用户的评估与豁免写入必须串行，分桶判定、宽限起算、强制标记与计数之间不得插入其它变更；重启或快照恢复后阶段、宽限截止时间、豁免到期时间、已强制集合与计数原样回来，已强制用户不得因恢复失去强制，豁免也不得被恢复延长。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: mfa_rollout_governor
- typeName: MfaRolloutGovernor
