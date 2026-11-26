# batch50-py-game-a-03-p5

## 题面

音游赛被申诉缠住：同一成绩两次回放连击不同；长条中途松手再按连击竟接上；开局第一个音符改过校准后整段消失。范围是 gsb/batch50-py-game-a-03-p5 的 rhythm_chart_judge.py，类 RhythmChartJudge，按谱面音符与输入时间戳判 Perfect/Great/Miss、处理长条与尾判、应用校准偏移。

公开接口：load_chart(notes)、calibrate(offset_ms)、press(time_ms, lane)、release(time_ms, lane)、tick(time_ms)、pause/resume、judge(note_id)、combo、accuracy、results、snapshot、restore、stats，拒绝抛 RhythmError(code, detail)。

故障与边界：①load_chart 校验 id 唯一、时间升序、lane 非负、长条时长正，否则 RHYTHM_CHART_INVALID；②|delta|≤40 判 perfect、≤80 判 great，超出返回 none 交 tick 记 miss，重复输入不得二次计分；③同 lane 多音符可取时取 |delta| 最小者，相同取时间更早的；④tick 把过窗待判音符记 miss 并清连击；⑤长条头按 press 判、尾按尾时间判，尾判成功加连击；⑥中途松开判断条、尾判 miss、连击清零，重按不恢复；⑦生效时间 = 输入时间 - 偏移；负偏移时开头音符不得被判早于谱面起点而丢弃；⑧尾判与下一音符同时可命中时，按时间先后判给更早者且不吞另一个；⑨pause 冻结判定，暂停期输入拒绝、tick 不推进；accuracy=(100*perfect+60*great)/已判数两位；⑩snapshot 深拷贝，restore 非法报 RHYTHM_SNAPSHOT_INVALID。

硬约束：输入与 tick 串行，同一音符并发命中计一次；快照恢复后判定状态、连击、最大连击与偏移都在且不共享结构。stats 含 presses、ticks、ignored、calibrations。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过、写死；并发自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: rhythm_chart_judge
- typeName: RhythmChartJudge
