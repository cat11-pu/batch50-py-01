# batch50-py-safety-c-01

## 题面

跳板机审计这周连开三张单：会话被审计代理接管后，剪贴板里突然冒出来路不明的长串，用户终端的光标凭空消失，窗口标题也被改成"请重新输入密码"；安全组复盘确认，有人往别人的 tty 里塞了回车和一整条下载执行命令，还成功把一组 OSC 写入复制到了宿主机剪贴板。同一台机器上两个录制任务盯住同一个伪终端，最后各写了一份半截日志，交接时谁也说不清哪份可信；机房断电重启后，那些没收口的录制段又被当成完整日志归档进了证据链。范围是 gsb/batch50-py-safety-c-01 的 tty_injection_guard.py，类 TtyInjectionGuard，负责 ioctl 准入、输出流过滤和分段录制落盘。审计侧的要求很具体：任何注入尝试都要留痕可查，任何被拦下的序列都要能从计数里对上账；录制不能因为一块数据没解析完就漏字节或改写字节，封口后的摘要必须能被独立复算。

公开接口：TtyInjectionGuard(record_dir, *, max_segment_bytes=1048576, blocked_osc=(52,), blocked_private_modes=("?25",))、on_ioctl(tty_id, request, arg=None)、open_session(tty_id, session_id)、filter_output(tty_id, chunk)、record(tty_id, data)、flush(tty_id)、close(tty_id)、update_rules(*, blocked_osc=None, blocked_private_modes=None)、recover()、segments(tty_id)、status(tty_id)、stats()。所有拒绝统一抛 TtyGuardError(code, detail)；filter_output 返回 OutputVerdict(emitted, pending, blocked)，record 与 flush 返回 SegmentInfo(tty, session, seq, path, status, bytes_written, sha256)，status(tty_id) 给出 owner、session、pending、open_segment、segments 五个字段。

故障与边界：①TIOCSTI(0x5412)、TIOCLINUX(0x541C) 一律拒绝，码为 IOCTL_BLOCKED_TIOCSTI / IOCTL_BLOCKED_TIOCLINUX，其余请求放行 IOCTL_ALLOWED；②单块内的 OSC 52 整段丢弃，blocked 记 "osc52"，不得把参数当正文吐出去；③CSI 私有模式 ?25 要拦成 "csi?25"，其他私有模式如 ?1049 照常放行；④转义序列被拆到多次写入时，未完成部分原样放进 pending，下次调用拼接后再判定；⑤普通文本与合法 SGR 原样透传，chunks_filtered 每次调用累加；⑥record 前必须 open_session，按 tty 分目录、session 加序号命名落盘，每写一次即 flush，段内字节顺序与写入顺序一致；⑦flush 封口给出完整 sha256 与字节数，重复 flush 返回 None 且不计数，封口后再写要开新段且序号递增；⑧单段累计超过 max_segment_bytes 的整块写入必须整体拒绝、不落盘；⑨close 封口并释放 tty，之后写入报 TTY_SESSION_CLOSED，重复 close 返回 None；⑩非字符串 chunk 抛 TTY_INVALID_CHUNK 且不计数，非法规则热更新抛 TTY_RULE_INVALID 并沿用旧规则；⑪同一 tty 同时只允许一个录制会话，第二个必须被拒而不是各写一份；OSC 52 即使被拆到多个块里也必须整体拦下；⑫录制段恰好在半个转义序列处中断时，这段残片不得当普通文本写进证据文件；重启后未封口的段要在 recover() 里封口、标记 incomplete 并计入 recovered。

硬约束：会话占用、规则切换与计数更新全部在锁内完成，并发 filter_output 与 record 不得串段或丢计数；重启恢复后已封口段不得被重复封口或重复计入 segments_closed。stats 固定返回 ioctl_calls、ioctl_blocked、chunks_filtered、sequences_blocked、bytes_blocked、segments_opened、segments_closed、segments_incomplete、recovered 九个键。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-01
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: tty_injection_guard
- typeName: TtyInjectionGuard
- topic: 终端会话注入防护：TIOCSTI 阻断、转义序列跨块解析与录制分段脱敏
