# batch50-py-safety-c-09

## 题面

补丁平台这周被审计挑了三个问题：一批 Exchange 补丁装完就显示已修复，其实要重启才生效，周报数字虚高；某台主机安装失败触发回退，回退脚本把上一批已经验证过的补丁一起卸了，业务直接不可用；还有两台机器在维护窗口之外被推进了下一批，值班电话响了一整晚。安全组要求这套下发必须能按批次解释清楚：谁该装什么、装到哪一步、失败之后撤了什么。范围是 gsb/batch50-py-safety-c-09 下的 patch_baseline_rollout.py，类名 PatchBaselineRollout，负责算缺失补丁、分批下发、按成功率推进、失败回退。

公开接口：PatchBaselineRollout(*, batch_size=50, success_ratio=0.9)；define_baseline(name, patches)；register_host(host_id, *, installed=(), exemptions=None, window=None)；in_window(host_id, *, now)；missing_for(host_id, *, now)；plan(*, now)；dispatch(batch_index, *, now)；on_result(host_id, patch_id, *, status, reboot_required=False, now=None)；confirm_reboot(host_id, *, now)；gate(batch_index)；rollback(batch_index, *, now)；batches()；status()；snapshot()、restore(state)、stats()。越界或冲突抛 RolloutError(code, detail)。

故障与边界：①基线只允许一份，同名同集合重定义按幂等返回版本 1；同名不同集合或换名再定义抛 ROLLOUT_BASELINE_CONFLICT。②缺失集合等于基线补丁减去已安装、再减去未到期豁免，按字典序返回元组；主机没登记过抛 ROLLOUT_HOST_UNKNOWN。③豁免带到期日，now 所在日期早于到期日才排除该补丁，到期当日及以后重新纳入。④plan 按主机名升序、每 batch_size 台一批并从 0 连续编号，跳过缺失为空的主机，返回批号到主机列表的映射，plan 本身不下发；配置过维护窗口的主机只有 now 落在窗口内才随批下发，否则留在原位等下一个窗口。⑤dispatch 必须按批号顺序推进：未 plan 抛 ROLLOUT_NOT_PLANNED，跳批抛 ROLLOUT_BATCH_OUT_OF_ORDER，同一批重复下发抛 ROLLOUT_BATCH_ALREADY_DISPATCHED，返回每条含 host_id 与 patches 的下发记录。⑥gate 返回 batch、installed、failed、total、ratio、passed；前一批安装成功率（installed 除以 total）低于 success_ratio 时，下一批 dispatch 抛 ROLLOUT_GATE_NOT_MET，同时整体置为暂停。⑦on_result 只接受该主机本批实际下发的补丁，其它组合抛 ROLLOUT_RESULT_UNKNOWN，状态不在 installed 与 failed 之内抛 ROLLOUT_RESULT_INVALID；同一主机同一补丁重复上报按幂等忽略、返回 False，计数只加一次。⑧需要重启才生效的补丁在 confirm_reboot 之前不得计入已修复，status 里 fixed 只统计确认生效的补丁，待重启的单独计入 pending_reboot。⑨rollback 只撤本批次下发并且已安装的补丁，把它们从已安装集合移回缺失，前一批已经成功的补丁不受影响。⑩门槛不足或者已经回退之后整体暂停，未下发的批次一律不得再 dispatch，回退次数按实际撤销的补丁计。⑪重启服务后已安装补丁不得重复下发：恢复结果状态之后 plan 与 missing_for 必须跳过它们。⑫status 汇总 baseline、hosts、batches、dispatched_batches、halted、fixed、failed、pending_reboot；stats 返回 planned、dispatched、installed、failed、duplicate_results、rolled_back 六项计数。

硬约束：同一主机同一补丁只会进入一次下发集合，plan、dispatch、on_result 之间必须串行，不得出现同一补丁重复计数或跨批重复下发；快照恢复后主机、豁免、维护窗口、批次、逐条结果、暂停标记原样回来，非法快照抛 ROLLOUT_SNAPSHOT_INVALID 且不改动现有数据。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: patch_baseline_rollout
- typeName: PatchBaselineRollout
