# batch50-py-safety-d-21

## 题面

运维组这周处理一块生产库的密钥轮换，连出三个状况。轮换脚本把新口令写进槽位后、删旧槽之前被中断，值班同事重启后又点了一次轮换，卷上多出一个同口令的槽，本来够用的槽位一下少了一半；另一台机器换盘后从头部备份恢复，盘符由 /dev/nvme0n1p3 变成 /dev/sdb3，脚本按路径找卷直接报找不到，备份本身是完好的；还有一次为了腾槽位，把卷上仅剩的一个密钥删掉，整卷当场解不开，只能拿离线备份救。安全组随后又翻出第四张单子：轮换失败的卷上有槽被标成不可用，摘要却还挂在记录里，别人拿旧口令照样能解，审计认定槽位没有真正回收。安全组要求把密钥槽治理做成可审计、可重试的事务，任何一步中断都能凭日志判断下一步做什么。范围是 gsb/batch50-py-safety-d-21 的 luks_keyslot_guard.py，类名 LuksKeyslotGuard，负责卷登记、密钥槽增删改、头部备份与恢复、审计留痕。

公开接口：LuksKeyslotGuard(*, max_slots=8, clock=None)；register_volume(volume_id, *, uuid, device_path, now) -> VolumeInfo；add_key(volume_id, *, passphrase, label="", key_type="luks2", now) -> Keyslot；change_key(volume_id, *, slot, old_passphrase, new_passphrase, now) -> Keyslot；remove_key(volume_id, *, slot, passphrase, now) -> int；backup_header(volume_id, *, now) -> HeaderBackup；restore_header(volume_id, backup, *, now) -> VolumeInfo；verify_header(volume_id, backup) -> bool；keyslots(volume_id)；pending_change(volume_id)；audit_log(volume_id)；stats()；snapshot()；restore(state)。拒绝时抛 KeyslotError(code, detail)。

故障与边界：①未登记卷抛 KEYSLOT_UNKNOWN_VOLUME，重复登记抛 KEYSLOT_DUPLICATE_VOLUME，槽号不存在抛 KEYSLOT_INVALID_SLOT。②同一口令不得同时占用两个槽，重复添加抛 KEYSLOT_DUPLICATE_KEY 且槽表一条不改；口令只以 SHA-256 摘要留档，明文不得出现在任何返回结构里，口令超过 512 字节抛 KEYSLOT_INVALID_PASSPHRASE。③槽位耗尽抛 KEYSLOT_EXHAUSTED，绝不覆盖已有槽；add_key 取当前最小空闲槽号，keyslots 按槽号升序。④变更口令先在新槽写入成功再删旧槽，新槽同样取最小空闲槽号并沿用旧槽的密钥类型；旧口令不匹配抛 KEYSLOT_WRONG_PASSPHRASE，一个槽都不动。⑤remove_key 必须校验该槽口令，不匹配抛 KEYSLOT_WRONG_PASSPHRASE；成功返回剩余可用槽数，回收后该槽的摘要、标签与时间一并清零，不留在卷记录里。⑥变更先写待决记录，旧槽删除成功才清除；中断后重试同一变更，pending_change 能看出新槽已写入，必须复用该槽而不是再占一个。⑦头部备份带单调递增版本，卷登记时版本为 1，每次改动头部加一；备份带 SHA-256 校验和，verify_header 对不上返回 False；恢复版本低于当前抛 KEYSLOT_BACKUP_STALE，校验和不符抛 KEYSLOT_BACKUP_CORRUPT，两种情况卷状态都不动。⑧恢复按卷 UUID 绑定，设备路径变化不算不匹配，恢复后卷记录跟随新路径。⑨审计先落盘再改头部，按发生顺序返回，action 取 register、add_key、change_key、remove_key、backup、restore，每条带 at、slot、result。⑩删除卷上最后一个可用槽必须拒绝，即使调用方声称手里有外部恢复密钥。⑪快照带结构版本与卷表，非法快照抛 KEYSLOT_SNAPSHOT_INVALID 且不改动现有状态。⑫stats 给出 volumes、keyslots、backups、changes、restores 五项计数。

硬约束：同一卷的槽位变更、头部备份与恢复串行，不同卷之间并行；快照与活动状态完全脱钩，恢复后槽表、备份引用、审计与计数原样回来，重启不得把已删除的槽借快照带回来。验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: luks_keyslot_guard
- typeName: LuksKeyslotGuard
