# batch50-py-safety-c-08

## 题面

堡垒机值班同学反馈：上周把十七台主机切成统一托管后，运维自己手写的注释行被整份覆盖，一条开发机临时密钥也跟着没了；某台机器的 expiry-time 填了 20261130，到点却没失效，另一台时区不同的主机却提前一天把人挡在门外；还有一次同一把公钥同时挂到两个账号，事后追责说不清到底是谁在用。安全组要求这套托管必须能说清每一行是谁写的、什么时候失效、为什么还在。范围是 gsb/batch50-py-safety-c-08 下的 authorized_keys_registry.py，类名 AuthorizedKeysRegistry，负责解析每行选项、按指纹去重、处理过期与来源限制，并把整份文件原子写回目标主机。

公开接口：AuthorizedKeysRegistry(*, dedup_policy="reject")；parse_line(line, *, account="")；upsert(account, line, *, now=None)；revoke(fingerprint, *, now=None)；render()；apply(path)；diff(path)；load(path, *, account, now=None)；entries(account=None)；quarantined()；audit_log()；snapshot()、restore(state)、stats()。文本不合规或操作被拒绝时抛 KeysError(code, detail)。

故障与边界：①一行由可选项、密钥类型、base64 主体和注释组成，只接受 ssh-ed25519、ssh-rsa、ecdsa-sha2-nistp256 三种类型，其它类型或主体无法解码时整行抛 KEYS_LINE_INVALID，且不写入任何状态。②指纹按 SHA256:<base64 编码后去掉尾部填充> 计算，同一主体不同注释必须得到同一指纹。③同一账号下同一指纹重复 upsert 视为更新：选项与注释覆盖、revision 加一、added_at 保持首次登记时间、行数不变。④同一指纹出现在不同账号时，默认策略抛 KEYS_FINGERPRINT_CONFLICT 并保持两边都不落库；dedup_policy 为 isolate 时把该指纹两处一并撤下并记入隔离名单。⑤revoke 只接受指纹，未知指纹返回 False 且计数不变；已知指纹撤销后进入墓碑，此后同一指纹再来（注释不同也一样）抛 KEYS_REVOKED。⑥render 按账号升序、同账号内按指纹升序输出，每条一行并以换行结尾，没有任何条目时返回空串。⑦from、command 这类带引号的选项必须原样保留引号、内部空格与排列顺序，no-pty 这类无值选项原样输出，不得重新格式化。⑧expiry-time 一律按 UTC 判定，跨时区主机上的本地时间不得参与比较，也不得因为主机时区不同得出不同结论。⑨同一行出现重复选项或互斥选项（例如两次 command）时整行拒绝，不得取最后一个生效。⑩渲染时保留其他工具写入的注释行，但必须丢弃无法解析的无效行。⑪apply 先整体校验再原子替换：写入失败抛 KEYS_APPLY_FAILED 且目标保持原字节，成功时内容与 render 完全一致并返回 path 与写入行数 written。⑫diff 对比目标文件与当前渲染结果，返回 added、removed 两个指纹列表与 unchanged 计数；load 把目标文件里合法的行读入指定账号，遇到无效行抛 KEYS_LINE_INVALID，已撤销的指纹不得复活。

硬约束：同一指纹的 upsert、revoke 与 apply 必须串行，去重判定与写盘之间不得插入其它变更；快照恢复后条目、revision、撤销墓碑、隔离名单、注释行与审计计数原样回来，非法快照抛 KEYS_SNAPSHOT_INVALID 且不改动现有数据。stats 返回 entries、upserted、updated、revoked、quarantined、applied、rejected 七项计数。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: authorized_keys_registry
- typeName: AuthorizedKeysRegistry
