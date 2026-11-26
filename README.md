# batch50-py-safety-a-09

## 题面

上线前的一轮认证器整改卡在证明策略上：同型号的两批设备，一批走 direct 证明被放行，另一批换了一条证明链根也被放行，安全同学核对之后发现那个根根本没在登记表里；还有人把元数据包回滚到上一个版本重新导入，系统只把新增条目补了进去，已经删掉的型号照样留在允许名单里；未知 AAGUID 的设备注册一次之后没有任何隔离记录，第二天原样又来注册一次；并发压测时同一台设备的评估结果一会儿是新版本一会儿是旧版本，明显读到了半份元数据。范围是 gsb/batch50-py-safety-a-09 的 attestation_trust_policy.py，类 AttestationTrustPolicy，负责 AAGUID 元数据、证明格式策略、信任锚轮换与未知认证器隔离。

公开接口：AttestationTrustPolicy(*, rp_id, overlap_seconds=86400, minimum="none")；upsert_metadata(entry)、metadata_for(aaguid)、set_policy(order, minimum=None)、evaluate(aaguid, fmt, trust_path_root=None)、quarantine(aaguid, reason)、quarantined()、reload(package)、rotate_anchor(aaguid, new_root)、active_anchors(aaguid)、snapshot()、restore(state)、stats()，时间参数统一 now 取整秒。拒绝一律抛 AttestationError(code, detail)。entry 是 dict，键为 aaguid（32 位小写十六进制）、vendor、model、formats、anchors、version；upsert_metadata 与 metadata_for 返回归一化后的同一结构，formats 与 anchors 为去重排序后的元组，metadata_for 查不到抛 ATTEST_UNKNOWN；evaluate 返回 dict，键含 status、aaguid、fmt、code、metadata_version、cached；rotate_anchor 返回 dict，键含 aaguid、new_root、overlap_until；reload 返回 dict，键含 version、count；active_anchors 返回排序后的元组。

故障与边界：①aaguid 不是 32 位小写十六进制、vendor 或 model 去空白为空、formats 为空或含非法格式、version 非正，一律抛 ATTEST_INVALID；②同一 aaguid 同版本同内容重复登记幂等且不重复计 upserts，同版本不同内容或更低版本抛 ATTEST_CONFLICT；③格式强度依次为 none 弱于 indirect、indirect 弱于 direct、direct 弱于 enterprise；④未知 aaguid 首次评估返回 quarantined 并回 ATTEST_UNKNOWN、同时进入隔离名单，之后再评估抛 ATTEST_QUARANTINED；⑤评估顺序固定：先查隔离，再查型号是否支持该格式抛 ATTEST_FORMAT，再查格式是否在策略顺序内抛 ATTEST_FORMAT_NOT_ALLOWED，再查强度是否低于下限抛 ATTEST_WEAKER；⑥direct 与 enterprise 必须给出 trust_path_root，缺了抛 ATTEST_ANCHOR_MISSING；⑦另外两条必须处理：证明链根不在登记锚上时，即使 AAGUID 在允许名单里也必须拒绝（ATTEST_ANCHOR_UNTRUSTED），元数据包版本回退要整体拒绝加载、不能只保留新增条目（ATTEST_RELOAD）；⑧quarantine 返回 aaguid 与 reason 两个键，记录该 aaguid 与原因并计入 quarantined 计数，quarantined() 按字典序返回全部被隔离的 aaguid；⑨rotate_anchor 在 overlap_seconds 重叠窗口内新旧锚同时可用，窗口到期后只剩新锚，active_anchors 返回排序元组；⑩reload 用 package 的 version 与 entries 整体替换元数据集合并返回 version 与 count，包结构非法抛 ATTEST_INVALID 且原集合不变；⑪评估结果按 aaguid、格式、根、元数据版本与策略版本缓存，命中时 cached 为真，元数据版本前进后旧缓存不得再命中；⑫快照与恢复覆盖元数据、策略、锚、隔离名单与各项计数，结构非法抛 ATTEST_SNAPSHOT 且原状态不变。

硬约束：upsert_metadata、evaluate、reload、rotate_anchor 与快照全程持锁，并发评估只能读到完整的旧版本或完整的新版本，不得读到半份元数据；重载必须原子替换，失败不得污染当前集合；快照为深拷贝，恢复后策略、锚重叠窗口剩余时间与隔离名单与快照一致。stats 固定返回 upserts、reloads、evaluations、cache_hits、quarantined、rotations。

验收：`python3 -m pytest -q tests` 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发评估与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: attestation_trust_policy
- typeName: AttestationTrustPolicy
- file: attestation_trust_policy.py
