# batch50-py-safety-d-20

## 题面

SBOM 查询这周被客户挑了两处错：同一个组件明明已经声明不受影响，客户拿 1.4 版本一查却被告知有风险；另一处是证据附件早被清理，声明还挂着「不受影响」在对外输出。范围是 gsb/batch50-py-safety-d-20 的 vex_statement_ledger.py，类 VexStatementLedger，负责维护可利用性声明并在查询时给出结论。

公开接口：VexStatementLedger(*, default_evidence_ttl=None, clock=None)；assert_statement(*, product, component, vulnerability, status, justification=None, evidence_ref=None, introduced="0.0.0", until=None, fixed=None, expires_at=None, now=None)、query(*, product, component, version, vulnerability)、supersede(statement_id, *, status, justification=None, evidence_ref=None, fixed=None, until=None, now=None)、expire(now=None)、register_dependency(product, component, depends_on)、export()、history()、stats()、snapshot()、restore(state)；异常统一抛 VexError(code, detail)。

故障与边界：①状态只允许 not_affected、affected、fixed、under_investigation，其他值抛 VEX_INVALID_STATUS；②not_affected 必须带理由码与证据引用，缺理由抛 VEX_MISSING_JUSTIFICATION，缺证据抛 VEX_MISSING_EVIDENCE，理由码只接受 component_not_present、vulnerable_code_not_in_execute_path、vulnerable_code_cannot_be_controlled_by_adversary、inline_mitigations_already_exist 四个；③fixed 必须绑定修复版本，缺了抛 VEX_INVALID_REQUEST，查询时实际版本低于修复版本仍判 affected；④版本号按点分十进制逐段比较、缺位补零，非法版本串抛 VEX_INVALID_VERSION；⑤声明按 [introduced, until) 区间生效，同产品同组件同漏洞下与未失效声明区间重叠抛 VEX_RANGE_CONFLICT，要在同一区间改判必须走 supersede；⑥supersede 生成新的声明号、修订号加一，未给出的理由、证据、修复版本与区间沿用旧声明，旧声明退出生效表但历史保留，声明号查不到抛 VEX_STATEMENT_UNKNOWN；⑦history 只追加不删除，按写入顺序给出每次登记与取代的记录；⑧证据到期由 expire 把声明降级为 under_investigation 并保留原证据引用，返回降级条数；⑨查询先按产品、组件、漏洞精确匹配再按实际版本选声明，查不到才沿依赖关系传播，结论取最严重档：affected 高于 under_investigation，高于 fixed，高于 not_affected，同档取登记顺序靠前的；chain 首元素是组件本身，依赖按登记顺序展开；⑩导出按产品、组件、漏洞、引入版本排序，同样输入两次导出必须完全一致；⑪同一组件在同一产品存在两个不重叠版本区间时，查询必须按实际版本选中对应那条，不能取最后写入的那条；⑫证据引用指向的内部报告被删除后，声明要降级并保留原引用标识用于追溯；上游组件发布新版本修复后，下游产品的 not_affected 声明不能自动沿用，必须重新评估。

export 每项是字典，键为 statement_id、product、component、vulnerability、status、justification、evidence_ref、introduced、until、fixed、expires_at、revision；stats 返回 statements、active、superseded、downgraded、queries 五个计数。同一版本点上只允许一条生效声明，单次查询只引用一个声明号而不返回列表。

硬约束：assert_statement 与 supersede 共用一把 threading.RLock，区间查重、声明号分配与旧声明退场必须在一次迁移内完成，并发登记同一（产品、组件、漏洞）只能留下一条生效声明；snapshot 返回 version、statements、dependencies、counters 四个键且为深拷贝，restore 遇缺键或类型不符抛 VEX_SNAPSHOT_INVALID 且不改动现有声明与计数。

验收：`python3 -m pytest -q tests` 15 条必须全过；不得改测试、跳过、按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: vex_statement_ledger
- typeName: VexStatementLedger
- file: vex_statement_ledger.py
