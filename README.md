# batch50-py-safety-a-03

## 题面

财务侧接入富授权后连着出三类单子：同意页对同一笔付款反复弹，用户点完又被弹一次；刷新令牌后商户把单笔额度悄悄抬高，用户没再确认却照常扣款；还有一条明细特别长的请求被截断后仍然下发，最后少了一条地区限制。范围是 gsb/batch50-py-safety-a-03 的 rar_detail_ledger.py，类 RarDetailLedger，负责校验 authorization_details、生成同意页摘要与指纹，并在刷新链上判断新集合是收窄还是扩大；现在这些入口一调用就抛 NotImplementedError，线上等同于功能缺失。

公开接口：RarDetailLedger(*, max_details_per_grant=4, max_bytes_per_grant=1024, max_grants_per_client=8, grant_ttl=3600)；validate(details)、fingerprint(details)、display_lines(details)、submit(details, tenant, client_id, now)、merge(grant_id, details, now)、compare(grant_id, details)、refresh(grant_id, details, now)、grant_view(grant_id)、revoke(grant_id)、sweep_expired(now)、snapshot()、restore(state)、stats()。拒绝一律抛 RarError(code, detail)。

故障与边界：①payment 必须带正整数 amount_max、三位大写 currency 与非空 payee，account_info 的 actions 只能取 read 或 write 且不能为空，region 的 countries 必须是两位大写国家码，未知 type 直接拒绝，detail 指出出错字段名；②details 必须是非空列表且每项是字典，空列表的 detail 为 details，列表本身类型不对报 RAR_INVALID_REQUEST，tenant 或 client_id 为空白同样报 RAR_INVALID_REQUEST；③规范化按 type 升序，actions 与 countries 去重后升序，返回新结构且不得就地改调用方列表，视图里的 details 是规范化元组；④display_lines 每行形如 account_info: read, write、payment: 10.00 EUR -> acme、region: DE, FR，按 type 字典序排列，空集合返回空元组；⑤fingerprint 是规范集合的 sha256 十六进制摘要，带 sha256: 前缀，同一集合重复计算必须一致，额度变了摘要必须变；⑥merge 取并集，集合真的变大才把版本加一并刷新更新时间，并集没变化时版本与时间都不动且只计一次 deduped；⑦refresh 对同一集合保持原版本原时间，收窄时版本加一，扩大或换了收款方一律要求重新同意；⑧同一 type 出现两条明细时必须按归并后的集合算摘要与展示，不能因为数组顺序不同让同意页重复弹出；⑨刷新时金额上限被抬高必须判为扩大并要求重新同意，不能静默取并集后照常下发；⑩明细条数或总字节超限都整体拒绝，总字节超限不能截断末尾一条明细后继续；⑪每 client 的活动授权有硬上限，超限的 detail 为 client_id，撤销或过期后额度立刻恢复；⑫状态只有 active、revoked、expired 三种，撤销幂等，撤销或过期后再 merge、refresh 一律拒绝，未登记 grant 报 RAR_UNKNOWN_GRANT。

硬约束：同一个 grant 被多路并发 merge 时版本只能推进一次，返回的视图摘要必须一致，stats 的 merged 与 deduped 相加要等于调用次数，并发下不许出现两个线程各写一版导致版本跳号；快照固定含 version、grants、stats 三个键，是深拷贝，restore 校验结构，缺键或类型不对报 RAR_SNAPSHOT_INVALID 且原状态不被改动，恢复后版本号、指纹与状态继续可用，重启不能把已授予集合清空；展示摘要与指纹必须用同一份规范集合计算，不能各算各的。容量与字节上限是硬顶，超限当场拒绝而不是事后回收。stats 至少含 submitted、merged、deduped、refreshed、revoked、expired，其中 refreshed 只统计真正推进版本的刷新。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: rar_detail_ledger
- typeName: RarDetailLedger
