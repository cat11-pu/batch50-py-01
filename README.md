# batch50-py-safety-d-08

## 题面

骨干侧的长连接服务这周被反复重置：一次密钥轮换之后，在途报文被判签名不符，半分钟内掉了几十条连接；另一批设备在序列号跨过 32 位边界以后，一半报文被当成乱序丢弃；还有几台经过 NAT 的设备重连后被直接判成攻击，密钥链本身并没有变。范围是 gsb/batch50-py-safety-d-08 的 tcp_ao_guard.py，类 TcpAoGuard，负责 TCP-AO 的密钥链治理、段签名校验与连接绑定；这些入口目前调用即抛 NotImplementedError，现网只有裸 TCP。

公开接口：TcpAoGuard(*, max_chains=8, max_keys_per_chain=8, max_connections=64, window_size=64)；install_key(chain_id, key_id, secret, *, send=True, recv=True, now=None)、remove_key(chain_id, key_id, now=None)、key_chain(chain_id)、bind_connection(conn_id, chain_id, peer, src_port, dst_port, now=None)、rebind_connection(conn_id, src_port, dst_port, now=None)、unbind_connection(conn_id)、sign_segment(conn_id, seq, payload, key_id=None)、verify_segment(conn_id, seq, payload, mac)、rollover(chain_id, key_id, now=None)、status()、snapshot()、restore(state)、stats()。拒绝一律抛 TcpAoError(code, detail)。

故障与边界：①install_key 返回 KeyEntry，generation 从 1 递增，fingerprint 为 64 位小写十六进制且不含密钥明文，默认 send 与 recv 都为 True，第一条安装的密钥就是当前发送密钥，key_chain 按 generation 升序；②同一链内 key_id 重复报 TCPAO_KEY_CONFLICT，密钥条数按 max_keys_per_chain 封顶，超出报 TCPAO_CAPACITY_EXCEEDED；③bind_connection 记录 conn_id、chain_id、peer、src_port、dst_port 与 bound_at，链未登记报 TCPAO_UNKNOWN_CHAIN，同一 conn_id 改绑另一条链报 TCPAO_BINDING_CONFLICT，连接表按 max_connections 封顶，连接表条目在建连时一次写入，之后只由 rebind_connection 更新；④sign_segment 用当前发送密钥算 MAC，返回 SignedSegment 的 mac 为 64 位小写十六进制，显式指定 key_id 时必须存在且 send 为 True，否则报 TCPAO_UNKNOWN_KEY；⑤verify_segment 命中接收窗口且 MAC 一致时 accepted 为 True、reason 为 ok、key_id 为实际命中的代次，window_floor 推进到该 seq；MAC 不符 reason 为 mac_mismatch 且 key_id 留空，窗口内重复序号 reason 为 duplicate，低于 window_floor 减 window_size 加一的下界 reason 为 out_of_window，水位只增不减，命中过期序号不回退；⑥未绑定的 conn_id 验签报 TCPAO_UNKNOWN_CONNECTION，空 chain_id、空 key_id、seq 为负报 TCPAO_INVALID_REQUEST；⑦rollover 把指定代次设为发送密钥，旧代次 send 变 False、recv 保持 True，未登记的 key_id 报 TCPAO_UNKNOWN_KEY；⑧序列号按 32 位或 64 位扩展维护，跨过 2^32 以后启用扩展格式，扩展前后的序号不能塞进同一个窗口直接比较；⑨rollover 之后旧密钥仍在接收窗口内，在途的旧密钥签名段必须能验过，不能因为新密钥启用就立刻拒绝；⑩连接被 NAT 重写后四元组变化而密钥链未变时，按 conn_id 用 rebind_connection 重新绑定，不能直接判成攻击或擅自换链，重绑定只更新端口与时间，不重置序列号窗口；⑪同一代次密钥被多路并发安装时只允许一个成功，其余报 TCPAO_KEY_CONFLICT，失败计数按对端聚合。

硬约束：verify_segment、sign_segment 与 rollover 并发时用同一把可重入锁保护密钥代次与序列号窗口，同一段被多路并发验签只能接受一次，计数不得翻倍，也不能出现一半接受一半判重复；快照固定 version、chains、connections、sequences、counters、stats 六个键，是深拷贝，restore 逐项校验结构，缺键、版本不符或类型不对报 TCPAO_SNAPSHOT_INVALID 且原状态不被改动，恢复后密钥链、发送密钥、序列号水位与已收序号继续生效，重启不能把窗口清空成全部可收。status 返回 chains、connections、keys、segments，四项均为条数；stats 至少含 installed、bound、signed、verified、mac_mismatches、duplicates、out_of_window、rollovers。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: tcp_ao_guard
- typeName: TcpAoGuard
