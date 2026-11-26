# batch50-py-safety-c-22

## 题面

上传通道上个月出了三件事：一份带宏的投标文件在扫描服务卡死后被当成“暂时无法判定”放了过去，第二天从租户共享盘里扩散开来；同一份文件被前端重试了七次，扫描队列里排了七份，扫描集群直接被自己的重试打满；还有一次安全同学把隔离区的样本手工放了行，隔天同样的内容又带着旧结论直接过了缓存，事后没人说得清是谁放行的。范围是 gsb/batch50-py-safety-c-22 下的 upload_scan_gate.py，类名 UploadScanGate，负责按内容哈希去重入队、扫描裁决、超时隔离、人工放行与缓存有效期管理。

公开接口：UploadScanGate(*, cache_ttl=300, scan_timeout=60, max_queue=8, max_bytes=1048576)；submit(upload_id, data, *, now)；claim(*, now)；complete_scan(digest, *, outcome, now)；verdict(upload_id)；queue()；cache_lookup(digest, *, now)；quarantine(digest, *, reason, now)；release(digest, *, actor, now)；sweep(*, now)；stats()、snapshot()、restore(state)。拒绝时抛 ScanGateError(code, detail)。

故障与边界：①upload_id 不能为空且不得重复，data 只接受非空 bytes 或 bytearray，长度不得超过 max_bytes，否则抛 SCAN_INVALID_REQUEST，失败的提交不得进入队列也不计入任何计数。②摘要取 sha256 的小写十六进制；同一摘要的多份上传只保留一个队列条目，先提交的 upload_id 排在前面，后提交的共享同一份裁决；submit 返回 upload_id、digest、state，verdict 返回 upload_id、digest、state、decision、reason、source，queue 返回按提交顺序排列的摘要元组。③claim 按提交顺序取队首，返回 digest、upload_ids、started_at，队列为空返回 None；被取走的摘要进入 scanning，不得被第二次 claim。④complete_scan 只接受 benign 与 malicious，其它取值抛 SCAN_INVALID_REQUEST；摘要未知抛 SCAN_UNKNOWN_DIGEST；尚未 claim 或已经结算抛 SCAN_STATE_INVALID，同一摘要不得结算两次；成功时返回 digest、outcome 与 cached。⑤良性结论对外 allow 并写入缓存，缓存条目带 created_at 与 expires_at；恶意结论对外 deny、原因为 malicious_content，且不得写入缓存，相同内容再次上传必须重新排队扫描。⑥提交时命中未过期缓存直接给出 allow 且不占用队列名额，source 为 cache；缓存过期后同一摘要再次提交必须重新排队扫描，不得沿用旧裁决，回源期间其它摘要的提交与查询不得被阻塞。⑦扫描超时按 started_at 加 scan_timeout 判定，到点后该摘要进入隔离区，对外表现为 deny、原因为 scan_timeout，队列中不得残留。⑧隔离区只能人工放行：release 的 actor 去空白后不能为空，否则抛 SCAN_ACTOR_REQUIRED；只允许从隔离状态放行一次，重复放行抛 SCAN_ALREADY_RELEASED，非隔离状态抛 SCAN_STATE_INVALID，未知摘要抛 SCAN_UNKNOWN_DIGEST。⑨放行后的结论 source 与 reason 都是 manual_release；放行属于人工处置，不得把良性结论写回缓存。⑩队列长度上限为 max_queue，超限抛 SCAN_QUEUE_FULL；正在扫描的摘要不占队列名额，claim 之后名额立即释放。⑪quarantine 可对排队或扫描中的摘要执行，原因不能为空，执行后队列条目移除、所有关联票据转为 deny。⑫stats 返回 submitted、queued、scanned、cache_hits、timed_out、released 六项计数；非法快照抛 SCAN_SNAPSHOT_INVALID，且不得改动现有票据、队列与缓存；快照键为 format、tickets、jobs、queue、cache、counters。

硬约束：同一摘要的提交、认领与结算必须串行，同一摘要并发提交只允许出现一个队列条目、共享同一份裁决，计数不得重复；快照必须与活动状态完全脱钩，恢复后票据、扫描中状态、隔离原因、缓存有效期与六项计数原样回来。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: upload_scan_gate
- typeName: UploadScanGate
