# batch50-py-game-a-15

## 题面

新赛季开服当晚，邮件系统连着出四起事故：活动邮件里三件附件，玩家背包只剩两个格子，点“全部领取”时前两件进了包，第三件报失败，邮件却已经标成已领取，玩家背包里少一件、客服补发时又和日志对不上；另一封邮件玩家先领了武器、药水没领，到期后系统把三件附件整封退回给发件人，发件邮箱里出现了两把已经到手的武器；同一封邮件被点两次领取，第二次又发了一遍金币；还有过期邮件的附件退回记录重复生成，运营盘点时仓库凭空多出一批道具。问题集中在游戏内邮件的附件领取与到期退回，改动范围是 gsb/batch50-py-game-a-15 的 mail_attachment_claim.py，类名 MailAttachmentClaim，按邮件维护附件清单，校验玩家背包格位，处理单件领取、整封领取、到期退回与退回记录。所有时间由调用方以毫秒整数传入。

公开接口：MailAttachmentClaim(*, bag_slots=40, max_attachments=5, default_ttl_ms=None, bag_writer=None)；send_mail(mail_id, *, sender, recipient, attachments, sent_at, expires_at=None)；claim_attachment(mail_id, *, player, attachment_id, now)、claim_all(mail_id, *, player, now)；expire_mail(mail_id, *, now)、expire_due(*, now)；mail_view(mail_id)、inbox(player)；bag_of(player)、returns_for(sender)；snapshot()、restore(state)、stats()。attachments 是含 item_id、count、slots 的字典序列，slots 缺省为 1。拒绝统一抛 MailError(code, detail)。

故障与边界：①mail_id 重复抛 MAIL_DUPLICATE_ID，收发双方为空、附件为空或超过 max_attachments、数量或格位非正整数、expires_at 不晚于 sent_at 抛 MAIL_INVALID_REQUEST；②附件按登记顺序编号自 1 起，邮件初始状态 active，全部领完转 empty，过期扫描后转 expired，inbox 按 mail_id 升序返回；③领取人必须是收件人，否则 MAIL_NOT_RECIPIENT，未知邮件或未知附件编号抛 MAIL_NOT_FOUND，已领取的附件再领抛 MAIL_ALREADY_CLAIMED；④单件领取先按该附件的 slots 校验背包剩余格位，不足抛 MAIL_BAG_FULL 且不得改动邮件与背包；⑤整封领取要求所有未领附件的格位总和一次放得下，放不下整封拒绝，不允许先塞一部分；⑥领取成功要同时写背包格位、道具堆叠与附件标记，三者计数一致，bag_of 的 items 按 item_id 升序；⑦过期判定以 now 严格晚于 expires_at 为准，过期邮件领取抛 MAIL_EXPIRED；⑧到期退回只为未领取的附件生成退回记录，记录带发件人、道具、数量、格位与扫描时刻，return_id 由邮件号与附件编号拼成，重复扫描同一封邮件不得重复生成；⑨expire_due 只处理已到期且尚未扫描过的邮件，按 mail_id 升序返回，再次调用返回空；⑩玩家背包容量固定，任何一次领取都不得让已用格位超过 bag_slots，未知玩家的背包为空包；⑪快照包含 version、mails、bags、returns、counters、stats，mails 与 bags 以编号或玩家为键，深拷贝不与内部共享，恢复时版本、结构或类型不符抛 MAIL_SNAPSHOT_INVALID 且原状态不变；⑫stats 固定返回 mails、active、empty、expired、claims、claimed_items、returned_items、expiries、bag_write_failures 九项。

运营侧另外强调两条：领取时如果背包写入这一步失败，必须把本次领取标记和内存里的格位占用一起回滚，不能出现邮件显示已领取而道具没进背包；同一封邮件部分领取后过期，只退回没领的部分，已经领走的部分不得再退一次。

硬约束：领取、到期、快照共用一把锁，同一附件并发领取只能有一个成功，其余必须拿到 MAIL_ALREADY_CLAIMED，背包与统计不得多算；快照恢复后邮件状态、附件标记、背包占用、退回记录与全部统计必须和恢复前一致；单封邮件附件数与玩家背包格位都是硬上限。验收运行 `python3 -m pytest -q tests`，15 条全部通过；不得修改测试、跳过用例或按固定输入写死；并发与恢复场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: mail_attachment_claim
- typeName: MailAttachmentClaim
