# batch50-py-safety-c-29

## 题面

账号中心这周被同一个问题反复打回：有员工把公司邮箱绑到个人账号后，又用同一邮箱注册了新账号，两个账号都能登录，审计查不出哪个才是本人；有用户把唯一的登录方式解绑后账号彻底登不进去，只能人工申诉；两个账号合并后，旧账号的登录标识仍然能登进那个已被合并的空壳，日志里出现两套身份；还有用户解绑后马上又绑回去，绕过了风控的观察期，而另一批用户把解绑的邮箱给同事用却立刻生效，规则解释不清。范围是 gsb/batch50-py-safety-c-29 下的 identity_link_registry.py，类名 IdentityLinkRegistry，负责外部身份与账号的唯一绑定、解绑保护、解析与账号合并墓碑。

公开接口：IdentityLinkRegistry(*, max_links_per_provider=8, cooldown_seconds=86400)；create_account(account_id, *, now=None) 返回 Account（含 account_id、state、created_at、link_count）；link(account_id, *, provider, external_id, now=None) 返回 LinkRecord（含 account_id、provider、external_id、sequence、linked_at）；unlink(account_id, *, provider, external_id, now=None)；resolve(provider, external_id)；merge_accounts(source, target, *, now=None) 返回 MergeResult（含 source、target、state、moved、dropped、merged_at）；list_links(account_id)；status(account_id)；tombstone_of(account_id)；accounts()；snapshot()、restore(state)、stats()。拒绝时抛 IdentityLinkError(code, detail)。

故障与边界：①create_account 的 account_id 去空白后不能为空，重复创建返回原记录且不重复计数；已合并的账号再创建抛 IDENTITY_ACCOUNT_TOMBSTONED。②link 要求 provider 与 external_id 非空，账号未知抛 IDENTITY_ACCOUNT_UNKNOWN，账号已墓碑抛 IDENTITY_ACCOUNT_TOMBSTONED。③同一外部身份全局只能绑定一个账号，被他人占用抛 IDENTITY_LINK_TAKEN；同一账号重复绑定同一身份按幂等处理，返回原记录、sequence 不变。④同一账号同一 provider 的绑定数达到 max_links_per_provider 后新增抛 IDENTITY_LINK_LIMIT，其它 provider 不受影响。⑤unlink 删除成功返回 True，键不存在返回 False；账号只剩一条绑定时必须拒绝并抛 IDENTITY_LAST_LOGIN，不得把账号弄成无法登录。⑥解绑后该外部身份可立即被其他账号绑定，但同一账号在 cooldown_seconds 内重新绑定同一身份抛 IDENTITY_COOLDOWN。⑦resolve 对已绑定身份返回 account_id、provider、external_id，未绑定返回 None。⑧merge_accounts 把 source 的全部绑定迁到 target，返回 moved 与 dropped；target 已有同一身份时丢弃 source 侧重复项，source 转为 tombstoned 并记下 merged_into 与合并时间。⑨合并后原账号标识不得再被新登录解析到。⑩合并前后都要守住 target 的每 provider 上限，超限时抛 IDENTITY_LINK_LIMIT 且 source 保持 active、绑定原样保留。⑪list_links 按 provider 与 external_id 升序，tombstoned 账号返回空；status 返回 account_id、state、merged_into、link_count、providers；accounts 列出全部账号标识。⑫快照含 version、accounts、links、tombstones、cooldowns、stats 六个顶层键且与活动状态完全脱钩；恢复非法结构抛 IDENTITY_SNAPSHOT_INVALID 且不得改动现有数据。stats 返回 accounts_created、links_created、links_removed、merges、cooldown_hits，冷却期拒绝时 cooldown_hits 加一。

硬约束：同一外部身份的绑定、解绑与账号合并必须串行，唯一性检查、绑定迁移与墓碑写入之间不得插入其它变更，合并失败时两边都不能留下半迁移数据；重启或快照恢复后绑定、墓碑、冷却时间与计数原样回来，已合并账号不得因恢复变回可登录状态，冷却也不得被恢复清零。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: identity_link_registry
- typeName: IdentityLinkRegistry
