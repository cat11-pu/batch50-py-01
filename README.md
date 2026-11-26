# batch50-py-safety-b-02

## 题面

运维值班这周被 FTP 反弹投诉拖住了：一台对外提供下载的 FTP 服务被当成端口扫描跳板，攻击者登录后连续下 PORT 命令，把数据连接指到内网其它主机；另一批客户在 NAT 后面，PASV 返回的私网地址根本连不上。范围是 gsb/batch50-py-safety-b-02 下的 ftp_bounce_guard.py，类 FtpBounceGuard，负责在单条控制连接上维护认证态、缓冲命令、校验数据连接目标并改写 PASV 应答。

公开接口：FtpBounceGuard(*, control_peer, pasv_port_range=(40000, 40100), active_peer_port=20, max_line=512, users=None, pasv_advertised_ip="192.168.10.20")；authenticate(user, password)；feed(chunk)；on_command(line)；authorize_data(peer_ip, peer_port)；rewrite_pasv(advertised_ip, port)；pending_data()；release_data()；snapshot()、restore(state)、stats()、close()。命令返回 Reply(code, text)，拒绝数据连接时抛 FtpGuardError(code, detail)。控制连接对端地址由 control_peer 固定。

故障与边界：①命令可能跨 TCP 分段到达，feed 要按行缓冲，凑满一行才处理，返回本次完成的所有应答；②单行超过 max_line 要整行丢弃并回 500，不能把它拼进下一条命令；③未认证时除 USER、PASS、QUIT 外一律回 530；④USER 回 331，PASS 正确回 230、错误回 530 且保持未认证；⑤PORT 与 EPRT 指定的地址必须等于 control_peer、端口必须等于 active_peer_port，否则回 501；⑥PORT 指向同一主机但换用非标准端口也必须拒绝，否则等于开放本机端口探测；⑦EPSV 只回端口，仍要校验分配的端口落在 pasv_port_range 内；⑧PASV 返回私网地址而控制对端是公网时必须改写为 control_peer，改写后仍要保留端口范围校验；⑨同一会话只允许一个待建立的数据连接，再来一个数据命令回 503；⑩authorize_data 在对端地址与待连接目标不一致时抛 FTP_DATA_PEER_MISMATCH；⑪拒绝某个目标后控制通道必须继续可用，后续 NOOP 照常回 200；⑫close 之后所有命令回 421，认证态与待连接目标清空。

硬约束：一是所有会话状态变更要在同一把锁内完成，feed 的缓冲、认证态、待连接目标不能被并发调用撕裂；二是 snapshot 固定包含 version、authenticated、user、buffer、pending、counters、closed 七个键并返回深拷贝，restore 还原后认证态、缓冲、待连接目标与计数都要一致。stats 至少给出 commands、rejected、line_too_long、pending_rejected、rewritten、data_authorized。

补充口径：Reply 至少含 code 与 text，DataTarget 至少含 ip、port、mode、mapped，mode 只有 active 与 passive 两种；EPRT 的协议号只接受 1 和 2，格式不合法同样回 501；PORT 与 EPRT 成功回 200，PASV 回 227，EPSV 回 229。待连接目标在 authorize_data 成功或 release_data 之后才允许替换。统计里 rejected 与 pending_rejected 分开计数，不能混在一起，被限流或格式拒绝的命令也要计入 rejected。feed 一次可能收到多行，要按到达顺序逐条返回应答，缓冲里剩下的半行留到下一次；NAT 改写只改地址不改端口，公开地址原样返回时不计改写。认证失败次数不设上限但每次都要回 530；目标校验失败时不得记录为待连接目标，也不得占用待连接名额；authorize_data 失败不清除原有待连接目标，控制通道继续可用；commands 只统计 feed 与 on_command 处理的行，authenticate 不计入。

验收：在包目录执行 python3 -m pytest -q tests，15 条必须全过；不得修改测试、跳过或用固定输入写死；分段到达与恢复自行验证；只做本地实现，不连真实 FTP 服务。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: ftp_bounce_guard
- typeName: FtpBounceGuard
