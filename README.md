# batch50-py-safety-c-13

## 题面

漏洞披露协调组上个月被一条时间线拖进了被动局面：厂商在确认收到报告后一直没给出修复截止日，协调员手工算了七十多天后又把两个法定节假日算了进去，实际期限比对外承诺的晚了四天；另一个条目在双方同意提前公开之后，前一位值班同学以为还能再申请一次延期，结果系统没有拦住，公告与补丁时间彻底错开。更常见的是重启后延期次数归零，同一漏洞被反复宽限。范围是 gsb/batch50-py-safety-c-13 下的 disclosure_embargo_clock.py，类名 DisclosureEmbargoClock：负责受理确认、按工作日计算修复截止、延期额度控制、提前公开申请与解禁闸门，并把条目和延期历史序列化以便重启恢复。

公开接口：DisclosureEmbargoClock(*, max_extensions=2, max_total_days=90)；set_holidays(days)；is_business_day(day)；open(advisory_id, *, product, fix_window_days, reported_at)；ack(advisory_id, *, now)；extend(advisory_id, *, days, now)；request_public(advisory_id, *, actor, now)；lift(advisory_id, *, now)；state_of(advisory_id)；history(advisory_id)；days_remaining(advisory_id, *, now)；snapshot()；restore(state)；stats()。拒绝时抛 EmbargoError(code, detail)，条目用只读对象 AdvisoryState 返回（含 advisory_id、product、state、reported_at、acknowledged_at、fix_due、lifted_at、extensions_used、extension_days、public_approved、public_actor）。

故障与边界：①open 要求 advisory_id 与 product 为非空字符串、fix_window_days 为 1 到 180 的整数，否则分别抛 EMBARGO_BAD_REQUEST 与 EMBARGO_BAD_WINDOW；重复 advisory_id 抛 EMBARGO_DUPLICATE；新条目状态为 reported，fix_due 为空。②ack 只能作用于 reported 状态，否则抛 EMBARGO_BAD_STATE；确认时间写入 acknowledged_at，fix_due 从确认日的次日起按工作日顺延 fix_window_days 天，周末与 set_holidays 登记的节假日跳过，输出 YYYY-MM-DD。③is_business_day 对周一至周五且不在节假日集合的日期返回真；set_holidays 接受 YYYY-MM-DD 集合、重复登记幂等，返回当前节假日数量。④extend 只能在 acknowledged 状态发起，未确认抛 EMBARGO_BAD_STATE；days 必须为正整数，否则 EMBARGO_BAD_REQUEST；返回 granted_days、extension_days、extensions_used、fix_due 与 truncated。⑤延期次数受 max_extensions 限制，用满后继续申请抛 EMBARGO_EXTENSION_LIMIT；每次成功延期把 granted_days 按工作日顺延到 fix_due 并写入 history。⑥延期总时长受 max_total_days 约束：申请量加上已用时长超过上限时，按剩余额度截断生效并把 truncated 置真，而不是整单拒绝；只有剩余额度为零时才抛 EMBARGO_EXTENSION_LIMIT。⑦解禁后状态为 embargo_lifted 并记录 lifted_at；此后任何延期、再次解禁或重复公开申请都必须抛 EMBARGO_ALREADY_LIFTED，状态不可回退。⑧request_public 只能在 acknowledged 状态发起，记录 actor 与 public_approved 表示双方同意提前公开，返回 advisory_id、public_approved、actor 与 at；解禁闸门为 fix_due 已到或 public_approved 为真。⑨lift 在闸门不满足时抛 EMBARGO_NOT_ELIGIBLE，成功时写 lifted_at 并落一条 history；days_remaining 按 now 的日期与 fix_due 的日历天差计算，已过期返回负数。⑩state_of 对未知条目抛 EMBARGO_UNKNOWN；history 按发生顺序返回 action、at、detail 三段结构，至少覆盖 ack、extend、request_public、lift。⑪快照包含版本、条目、节假日集合与计数，恢复非法结构抛 EMBARGO_SNAPSHOT_INVALID 且不改动现有条目。⑫重启后已用延期次数、累计天数、fix_due 与解禁状态原样恢复，不能重新获得延期额度；stats 返回 opened、acknowledged、extended、lifted、extension_days 五项。

硬约束：同一条目的 ack、extend、request_public、lift 必须串行，两个并发延期只能有一个按当时的剩余额度生效，延期次数与累计天数不得被写重；快照与恢复必须原子，恢复失败不得留下半更新的条目，已解禁条目不得借恢复回到可延期状态。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: disclosure_embargo_clock
- typeName: DisclosureEmbargoClock
