# batch50-py-safety-c-15

## 题面

代码托管平台的凭据泄漏处置链路在上次演练中暴露出三个断点：同一个云访问密钥先后出现在两个仓库、三个提交里，处置台把它们当成三条独立发现，吊销工单开了三张，轮换完成后还有两条一直挂在待验证；另一个已确认失效的指纹被标记为已处置，两周后同一条密钥以明文再次提交，值班同学只在旧记录上改了状态，新的暴露位置和提交信息全丢了；还有一次验证服务返回超时错误，结论却被缓存成有效，差点按有效密钥继续放行。范围是 gsb/batch50-py-safety-c-15 下的 secret_leak_triage.py，类名 SecretLeakTriage：负责按密钥指纹归一发现、记录跨仓库跨提交的出现位置、缓存验证结论、串联吊销工单与主记录处置状态。

公开接口：SecretLeakTriage(*, verify_ttl_seconds=3600)；ingest(finding_id, *, repo, commit, path, fingerprint, now)；verify_result(fingerprint, *, verdict, now)；dedupe(fingerprint)；open_revocation(fingerprint, *, provider, owner, now)；close_revocation(ticket_id, *, resolution, now)；close_finding(fingerprint, *, resolution, now)；status(fingerprint)；findings(*, state=None)；revocations(*, state=None)；snapshot()；restore(state)；stats()。拒绝时抛 LeakError(code, detail)，主记录与工单分别用只读对象 LeakRecord、RevocationTicket 返回，时间统一为带 +00:00 偏移的 ISO 8601 字符串。

故障与边界：①ingest 要求 finding_id、repo、commit、path、fingerprint 均为非空字符串，重复 finding_id 抛 LEAK_DUPLICATE_FINDING，字段不合法抛 LEAK_BAD_REQUEST。②指纹是归一化主键：同一指纹跨仓库跨提交只保留一条主记录并累计 occurrences，locations 按 repo、commit、path 升序去重；不同 finding_id 命中同一指纹时 duplicate_location 为真，主记录状态不变，first_seen_at 保留最早时间、last_seen_at 取最新时间；ingest 返回 finding_id、fingerprint、master_state、duplicate_location、occurrences。③新指纹的主记录状态为 pending_verification，verdict、verified_at、verify_expires_at、disposed_at 为空。④verify_result 的 verdict 只能取 valid、invalid、error，否则抛 LEAK_BAD_VERDICT；未知指纹抛 LEAK_UNKNOWN；valid 置 valid、invalid 置 invalid、error 只记录失败并保持待验证；每次写入 verified_at 与按 verify_ttl_seconds 计算的 verify_expires_at。⑤验证结论有缓存有效期：过期结论既不得当作有效也不得当作无效，主记录必须保持待验证并允许重新验证，不得沿用过期结论放行吊销。⑥open_revocation 只对 valid 主记录生效，pending、invalid 或 disposed 抛 LEAK_NOT_REVOCABLE；同一指纹已有未关闭工单抛 LEAK_REVOCATION_EXISTS；工单包含 ticket_id、fingerprint、provider、owner、state、opened_at。⑦close_revocation 关闭工单并记录 resolution、closed_at，返回 ticket_id、state、fingerprint、record_state；当一个指纹的最后一张未关闭工单关闭且主记录为 valid 时，主记录转 disposed 并记录 disposed_at。⑧close_finding 在主记录仍有未关闭工单时抛 LEAK_REVOCATION_OPEN；对 invalid 记录允许直接关闭为 disposed；未知指纹抛 LEAK_UNKNOWN。⑨主记录一旦 disposed，新发现同一指纹要新建事件并关联旧主记录，而不是把旧主记录改回未处置，也不得覆盖原处置时间。⑩status 返回 fingerprint、state、occurrences、locations、verdict、verified_at、disposed_at；findings 与 revocations 可按状态过滤并按标识升序。⑪快照包含版本、主记录、发现事件、工单与计数，恢复非法结构抛 LEAK_SNAPSHOT_INVALID 且不改动现有数据。⑫重启后 occurrences、位置集合、验证结论有效期与工单状态原样恢复，已处置记录不得回到待验证；stats 返回 ingested、occurrences、verified_valid、verified_invalid、disposed、revocations 六项。

硬约束：ingest、验证与吊销必须串行，同一指纹并发上报不得产生两条主记录或丢失位置；快照与恢复必须原子，恢复失败不得留下半更新的主记录或工单，已处置状态与已关闭工单不得被恢复改写。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: secret_leak_triage
- typeName: SecretLeakTriage
