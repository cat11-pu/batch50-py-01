# batch50-py-safety-c-27

## 题面

运营与账号团队这周收到一串升级单：匿名用户在结算前登录后购物车清空、上传的草稿丢失，工单里说“绑定成功了但东西没了”；另一批用户反复点绑定，有时提示已绑定、有时又悄悄返回同一个账号，客服无法判断到底绑没绑上；还有一次绑定进行到一半账号被风控冻结，结果匿名侧资源被清掉一半、账号侧也多了半份数据；同一个商品键在两边都有时，有人反馈账号里的偏好被匿名侧覆盖了。范围是 gsb/batch50-py-safety-c-27 下的 anonymous_identity_binder.py，类名 AnonymousIdentityBinder，负责匿名主体创建、资源挂载、绑定迁移、冲突合并与回滚。

公开接口：AnonymousIdentityBinder(*, conflict_policy="account_wins", max_resources_per_anon=64)；create_anon(*, device_id, now=None) 返回 AnonSession（含 anon_id、device_id、state、created_at、resource_count）；attach_resource(anon_id, *, kind, key, value, now=None) 与 detach_resource(anon_id, *, kind, key)；merge_state(anon_id, *, account_id, now=None) 返回合并预演；bind_to_account(anon_id, *, account_id, now=None) 返回 BindResult（含 bind_id、anon_id、account_id、status、migrated、added、conflicts、overwritten、bound_at）；rollback(account_id, *, now=None)；freeze_account(account_id)；status(anon_id)；anon_resources(anon_id)；account_resources(account_id)；list_anonymous()；snapshot()、restore(state)、stats()。拒绝时抛 AnonymousBindError(code, detail)。

故障与边界：①create_anon 要求 device_id 非空，返回 anon_ 加 12 位小写十六进制、state 为 active；空设备号抛 ANON_INVALID_REQUEST。②资源 kind 只接受 cart、draft、preference、upload，其它抛 ANON_BAD_KIND；key 或 value 为空串抛 ANON_INVALID_REQUEST。③同一 (kind, key) 重复挂载按更新处理，revision 从 1 开始逐次加一，资源条数不变；每个匿名主体的去重资源数达到 max_resources_per_anon 后新增其它键抛 ANON_RESOURCE_LIMIT，更新已有键不受限。④detach_resource 删除成功返回 True，键不存在返回 False；匿名主体未知抛 ANON_UNKNOWN。⑤merge_state 是只读预演，返回 migrated、added、conflicts、overwritten 与按 kind:key 升序的 keys，不改变任何一侧数据，也不消耗匿名主体。⑥bind_to_account 按预演结果迁移，返回 bind_id、status="bound"、migrated、added、conflicts、overwritten；成功后匿名主体 state 变为 bound、匿名侧资源清空，账号侧持有全部非冲突资源。⑦冲突合并时账号侧已有键的值保持不变，策略为 account_wins 时 overwritten 为 0；冲突键仍计入 migrated 与 conflicts，匿名侧独有的键必须原样落到账号侧。⑧已绑定的匿名主体再次绑定时必须返回 ANON_ALREADY_BOUND，不得静默返回原账号。⑨账号被 freeze_account 冻结后绑定抛 ANON_ACCOUNT_FROZEN，匿名主体保持 active、资源条数与内容不变，账号侧不得出现半份迁移数据。⑩rollback 按账号撤销最近一次成功绑定，返回 bind_id、anon_id、restored 条数；账号侧移除本次新增的键，匿名主体恢复 active 并拿回全部资源，没有可回滚绑定时抛 ANON_ROLLBACK_UNAVAILABLE；status 返回 anon_id、device_id、state、account_id 与 resource_count。⑪快照含 version、anonymous、accounts、binds、stats 五个顶层键且与活动状态完全脱钩；恢复非法结构抛 ANON_SNAPSHOT_INVALID 且不得改动现有数据。stats 返回 anonymous_created、resources_attached、bound、rolled_back、conflicts。

硬约束：同一匿名主体的挂载、绑定与同一账号的回滚必须串行，冲突判定、账号写入与匿名侧清空之间不得插入其它变更，失败时两侧都必须停在绑定前状态；重启或快照恢复后匿名主体状态、账号资源、绑定栈与计数原样回来，已绑定的主体不得因恢复退回可绑定状态，回滚也不得撤销其它账号的数据。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: anonymous_identity_binder
- typeName: AnonymousIdentityBinder
