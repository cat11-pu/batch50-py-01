# batch50-py-safety-c-06

## 题面

取证组这周连着提了三个问题：一起勒索案件的证据包在外部复检时无法自证来源，因为采集过程中设备被系统自动挂载成了可写状态，报告里却仍然显示完整；另一台笔记本采到一半断电，续采后块序号从头发了一遍，逐块摘要和最终摘要对不上；还有一起跨年案件，签名密钥换过之后旧条目全部报验签失败，保管链被判定断链。审计部门要求这三类问题在一周内闭环，每一次采集都要能独立解释来源与完整性，中途出过什么意外也必须留在台账上。范围是 gsb/batch50-py-safety-c-06 下的 evidence_acquisition_ledger.py，类名 EvidenceLedger，负责登记案件、声明采集源的写保护方式、按块累计摘要、生成只追加的保管链条目。

公开接口：EvidenceLedger(*, block_size=4096)；open_case(case_id, *, subject, now)；acquire(case_id, *, device_id, source_protection, now)；chunk(acq_id, *, index, data, now)；interrupt(acq_id, *, now)；resume(acq_id, *, now)；observe_write(acq_id, *, offset, length, now)；report_corruption(acq_id, *, index, now)；close(acq_id, *, now)；verify_chain(case_id)；entries(case_id)；chunks(acq_id)；snapshot()、restore(state)、stats()。任何拒绝都抛 EvidenceError(code, detail)。

故障与边界：①同一 case_id 重复 open_case 且 subject 相同按幂等处理，返回原记录，不新增链条目；subject 不同抛 EVIDENCE_CASE_CONFLICT。②source_protection 只接受 write-blocker 与 readonly-mount 两个取值，其它取值抛 EVIDENCE_SOURCE_UNPROTECTED。③同一设备同时只允许一个进行中的采集，第二个申请抛 EVIDENCE_DEVICE_BUSY，换设备不受影响。④块的 index 必须从 0 连续递增，跳号抛 EVIDENCE_CHUNK_GAP，重复抛 EVIDENCE_CHUNK_DUPLICATE，空数据抛 EVIDENCE_CHUNK_EMPTY。⑤每块摘要按 sha256(前一块摘要的字节 + 本块数据) 递推，首块以前一块为空串时的 sha256 摘要为前缀，逐块记录长度与摘要。⑥采集未成功关闭前不得封存，中断状态下 close 抛 EVIDENCE_STATE_INVALID。⑦interrupt 只对进行中的采集有效，resume 只对中断状态有效，其它情况抛 EVIDENCE_STATE_INVALID；续采从下一个块序号继续，不得重发已采块。⑧采集期间一旦上报设备写入或块校验失败，整份证据立即标记为污染或不可用，后续 chunk 与 close 一律拒绝，不得以最终摘要恰好一致为由放行。⑨同一案件里关闭后再次采集同一设备，必须生成新的采集号与新链条目，不得沿用旧摘要。⑩保管链条目只追加：seq 从 1 连续，kind 区分 case_open、acquire_open、chunk、interrupt、resume、seal，每条带签名时的密钥代次。⑪签名密钥可轮换，轮换后旧条目仍须按各自记录的代次验签成功，不得对全链重新签名。⑫案件、采集、块任一标识未知时抛对应的 EVIDENCE_*_UNKNOWN。

硬约束：同一设备的采集申请、同一采集的块追加与关闭必须串行化，块序号与累计摘要不得丢块、错序或重复入链；快照必须与活动状态完全脱钩，恢复后案件、进行中的采集、已采块、链条目、密钥代次与计数器原样回来，非法快照抛 EVIDENCE_SNAPSHOT_INVALID 且不得改动现有数据。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: evidence_acquisition_ledger
- typeName: EvidenceLedger
