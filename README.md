# batch50-py-safety-c-25

## 题面

合规审计在季度检查里挑出三个问题：某支付端点在上上轮扫描里悄悄关掉了 TLS 1.3，只留 TLS 1.2，台账里看不出来，直到外部扫描器报出来才承认降级；一个已经豁免的弱套件问题在豁免到期后没有任何动静，回归项永远显示已豁免；还有一个下线的端点被直接从台账里删掉，半年后要追溯它最后的证书签发者，翻遍历史都找不到。范围是 gsb/batch50-py-safety-c-25 下的 tls_posture_ledger.py，类名 TlsPostureLedger，负责逐轮记录端点 TLS 姿态、跨轮识别降级、维护带到期时间的豁免与裁剪历史轮次。

公开接口：TlsPostureLedger(*, history_rounds=3, cert_warning_days=30)；record_scan(round_no, *, endpoints, now)；diff_round(round_no)；regress(round_no)；waive(regression_id, *, until, reason, now)；resolve(regression_id, *, now)；regressions(*, state=None)；history(*, endpoint=None)；endpoint_state(endpoint)；summary(round_no)；sweep(*, now)；stats()、snapshot()、restore(state)。拒绝时抛 LedgerError(code, detail)。

故障与边界：①每轮扫描的 endpoints 必须非空，同一端点不得重复出现，协议只接受 TLSv1.0 到 TLSv1.3，套件列表、签发者、到期时间都不能为空，否则抛 TLS_INVALID_SCAN 且整轮不得入库。②轮次必须是正整数且严格大于上一轮，重复或倒退抛 TLS_ROUND_ORDER；第一轮可以是任意正整数。③协议与套件去重后按字典序以元组保存；证书到期时间按整数秒保存，不受主机时区影响。④与上一轮相比，协议集合变小开 protocol_downgrade 回归项，套件缺失开 suite_removed，签发者变化开 cert_issuer_changed，三项各自独立计数。⑤新增协议或套件只在 diff 里体现为 protocol_added、suite_added，不得开回归项；diff_round 返回 round、previous、changes，changes 按 endpoint 与 kind 的字典序排列。⑥证书剩余天数不足 cert_warning_days 时开 cert_expiring 回归项，detail 带 not_after 与 days_left；同一端点同一类问题只开一次，不重复编号。⑦回归项编号从 REG-0001 递增，带 regression_id、endpoint、kind、state、opened_round、detail 六个字段，state 取 open、waived、resolved。⑧waive 要求 reason 去空白后非空、until 严格大于 now、且回归项处于 open，否则抛 TLS_BAD_WAIVER；未知编号抛 TLS_REGRESSION_UNKNOWN；豁免成功后记录 waived_until 与 waive_reason。⑨resolve 允许 open 与 waived 转 resolved，已 resolved 再调用抛 TLS_REGRESSION_STATE；regressions 可按 state 过滤并按编号升序返回。⑩豁免到期后要自动重开，重开时沿用原回归项标识，便于追踪同一个问题；sweep 返回 reopened 与 pruned_rounds 两个计数。⑪端点整体消失时标记为不可达，最近一轮之外不得删除它的历史记录，endpoint_state 仍要能给出最后已知姿态，返回 endpoint、protocols、suites、cert_issuer、cert_not_after、last_round、unreachable 七个字段；历史只保留最近 history_rounds 轮，超出部分在 record_scan 时裁剪并在返回值里给出 round、endpoints、unreachable、pruned 四个字段。⑫diff_round、regress、summary 对未保留的轮次抛 TLS_ROUND_UNKNOWN，endpoint_state 对从未出现的端点抛 TLS_ENDPOINT_UNKNOWN，history 对未知端点返回空元组；summary 返回 round、endpoints、protocols、open_regressions、waived_regressions 五个字段；stats 返回 rounds、endpoints、regressions、waived、reopened 五项；非法快照抛 TLS_SNAPSHOT_INVALID 且不得改动现有轮次与回归项，快照键为 format、rounds、regressions、counters。

硬约束：同一台账上的轮次写入必须串行，轮次顺序、回归项编号与豁免状态之间不得插入并发写入，同一轮最多入库一次；快照必须与活动状态完全脱钩，恢复后轮次、端点姿态、回归项编号与状态、豁免到期时间与五项计数原样回来，已解决的回归项不得借快照回到 open。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: tls_posture_ledger
- typeName: TlsPostureLedger
