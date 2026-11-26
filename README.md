# batch50-py-safety-b-03

## 题面

媒体网关升级后出现一类偶发单通：SDP 里同一个媒体段的 fingerprint 行有两条，网关取了第一条，结果 DTLS 握手用的是另一张证书，SRTP 密钥算出来两边对不上；还有客户重协商删掉视频段后，旧 SRTP 上下文仍在发加密包。范围是 gsb/batch50-py-safety-b-03 下的 srtp_fingerprint_binder.py，类 SrtpFingerprintBinder，负责解析 SDP 媒体段、绑定证书指纹、核验对端证书并管理每个媒体段的密钥材料。

公开接口：SrtpFingerprintBinder(*, allowed_algorithms=("sha-256", "sha-384", "sha-512"), max_bindings=16)；parse_sdp(sdp)；bind_offer(sdp)；accept_answer(sdp)；verify_peer(mid, cert_der)；renegotiate(sdp)；key_material(mid)；release(mid)；bindings()；snapshot()、restore(state)、stats()、close()。解析结果用 MediaSection(mid, media, port, protocol, fingerprint_algorithm, fingerprint_value, setup)，绑定用 Binding(mid, algorithm, fingerprint, role, context_id, verified)。拒绝抛 SrtpError(code, detail)。

故障与边界：①解析 SDP 时 m= 行取媒体、端口与传输协议，a=mid、a=fingerprint、a=setup 按行读取，算法名统一小写、指纹统一大写；②媒体段缺 a=mid、同一段出现两个 fingerprint 行，整段拒绝，不能取第一条；③bind_offer 对每个媒体段只绑定一个指纹，缺 fingerprint 抛 SRTP_FINGERPRINT_MISSING；④指纹算法不在 allowed_algorithms 内抛 SRTP_ALGORITHM_NOT_ALLOWED，策略只允许 sha-256 及以上时出现 sha-1 必须拒绝，不得回退比较；⑤指纹十六进制长度必须与算法摘要长度一致，否则 SRTP_FINGERPRINT_INVALID；⑥accept_answer 的媒体段集合必须与 offer 完全一致，否则 SRTP_SDP_MISMATCH；⑦verify_peer 用绑定算法对 DER 证书求摘要，匹配返回 True 并把该段标记为已核验，不匹配整段拒绝并抛 SRTP_FINGERPRINT_MISMATCH；⑧被拒绝的媒体段再取 key_material 抛 SRTP_SEGMENT_REJECTED；⑨renegotiate 返回 added、removed、unchanged 三个元组，新增段要重新绑定，删除媒体段时该段的 DTLS 密钥与 SRTP 上下文必须同时销毁；⑩绑定总数不得超过 max_bindings，超限抛 SRTP_BINDING_CAPACITY 且不产生半成品绑定；⑪同一 mid 再次出现或指纹在协商中变化，按整段拒绝处理。

硬约束：一是绑定表与密钥材料要在同一把锁内更新，解析、绑定、核验、重协商不能交错出中间态；二是 snapshot 固定包含 version、bindings、counters 三个键并返回深拷贝，restore 还原后绑定、核验标记与计数一致，结构不合法抛 SRTP_SNAPSHOT_INVALID 且不改动现有状态。stats 至少给出 offers、answers、verified、rejected、renegotiations。

补充口径：MediaSection 的 fingerprint_algorithm 与 fingerprint_value 允许为 None，setup 缺失也允许；Binding 的 context_id 从 1 开始递增，已删除段的编号不再复用。renegotiate 失败时绑定表保持原样，不能删一半留一半；accept_answer 只校验媒体段集合与指纹格式，不代替 verify_peer 做证书核验。key_material 只在核验通过后可取，同一绑定重复取必须返回相同字节。解析失败的 SDP 不产生任何绑定，也不改动已有绑定；摘要计算只依赖标准库，算法名与摘要长度要对得上，长度不符直接拒绝。指纹比较忽略大小写与冒号分隔符，同段指纹变化按整段拒绝后，该段旧绑定与旧密钥一并作废。

验收：在包目录执行 python3 -m pytest -q tests，15 条必须全过；不得修改测试、跳过或按固定证书写死；重协商与恢复自行验证；只做本地实现，不引入第三方库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: srtp_fingerprint_binder
- typeName: SrtpFingerprintBinder
