# batch50-py-safety-c-21

## 题面

规则运营组这周被三次放行事故追着问：一条候选规则在历史样本上重放时，把基线根本没给出结论的样本算成了自己的新增命中，评审会上成绩很好看，上线后却是成片误报；另一条规则的回放跑到一半机器重启，续跑之后批次被重复累加，命中数直接翻倍，阈值判定形同虚设；还有一条规则只留了一句“通过”，没人说得清它对着哪个规则版本、哪份样本集版本做的判断，事后完全无法追溯。范围是 gsb/batch50-py-safety-c-21 下的 rule_backtest_gate.py，类名 RuleBacktestGate，负责装载基线规则、候选规则与历史样本集，分批回放，比较命中差异并在阈值内给出结论。

公开接口：RuleBacktestGate(*, batch_size=4, max_new_hits=3, max_fp_delta=2)；load_baseline(rule_id, *, version)；load_candidate(rule_id, *, version, selectors)；load_samples(sampleset_id, *, version, baseline_version, samples)；run_backtest(*, candidate, baseline, sampleset, batch_size=None, batch_limit=None)；interrupt(run_id)；resume(run_id, *, batch_limit=None)；progress(run_id)；compare_baseline(run_id)；decide(run_id)；report(run_id)；snapshot()、restore(state)、stats()。拒绝时抛 BacktestError(code, detail)。

故障与边界：①规则标识不能为空，version 必须是正整数，候选规则 selectors 去空白去重后按字典序以元组返回，空列表抛 BACKTEST_INVALID_RULE。②样本行必须带 sample_id、label（malicious 或 benign）、tags 列表与 baseline_state（hit、miss、absent 三者之一），sample_id 重复抛 BACKTEST_INVALID_SAMPLES，整行校验失败时样本集不得入库。③样本集记录的 baseline_version 必须与所装载基线规则的 version 一致，不一致时回放抛 BACKTEST_BASELINE_MISMATCH。④候选命中由 selectors 与样本 tags 求交集判定，候选命中数与基线命中数分别累计，processed 不得超过 total。⑤批次按 batch_size 切分，最后一批可以不满；batch_limit 达到时运行停在 paused，next_batch 指向待跑批次，续跑从该批继续，不得重复累加已经处理过的批次；run 与 resume 返回 run_id、status、total、total_batches、next_batch，progress 额外返回 processed、candidate_hits、baseline_hits。⑥interrupt 只对 paused 或 interrupted 有效，重复调用保持 interrupted，对已完成运行抛 BACKTEST_RUN_STATE，未知运行抛 BACKTEST_UNKNOWN_RUN。⑦compare_baseline 只接受已完成运行，未完成时抛 BACKTEST_RUN_NOT_READY；返回 scored、candidate_hits、baseline_hits、new_hits、candidate_fp、baseline_fp、fp_delta，分母取可比较样本而不是样本集总数。⑧new_hits 只统计基线为 miss 的样本；baseline_state 为 absent 的样本既不计入分母也不得计为候选规则的新增命中。误报按 benign 且被命中计，fp_delta 为候选误报数减基线误报数，可以为负。⑨decide 在 new_hits 不超过 max_new_hits 且 fp_delta 不超过 max_fp_delta 时返回 accept，否则 reject 并在 reasons 里按序给出 NEW_HITS_OVER_LIMIT、FP_DELTA_OVER_LIMIT，两项同时越界时两个都要列出。⑩结论必须带 run_id、candidate_version、baseline_version、sampleset_version；运行标识从 BT-0001 起递增，report 的 batches 每批只出现一次，每项含 batch_no、processed、candidate_hits，batch_no 从 1 连续。⑪stats 返回 baselines、candidates、samplesets、runs、accepted、rejected 六项计数。⑫非法快照抛 BACKTEST_SNAPSHOT_INVALID，且不得改动现有规则、样本集与运行记录；快照键为 format、baselines、candidates、samplesets、runs、counters。

硬约束：同一门禁上的装载、回放与结论必须串行，多个运行各自持有独立的批次游标与命中计数，互不串账；快照必须与活动状态完全脱钩，恢复后规则、样本集、运行游标、命中计数与结论原样回来，已完成的运行不得借快照回到未完成状态。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: rule_backtest_gate
- typeName: RuleBacktestGate
