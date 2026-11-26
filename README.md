# batch50-py-safety-c-03

## 题面

三个机房的运维同时报同一个怪事：内网镜像站被人替换后，主机上的包管理器照常安装，签名校验还显示通过；另一家供应商的 Release 文件已经过期半个月，主机代理仍把这个源算进候选，装出来的版本比已装的还旧，业务回滚直接失败。审计追问时又发现，同一把发布密钥被登记到了两个源上，谁都能拿它签；pin 规则一多，两台机器解析出的候选顺序还不一样，问题复现不了。范围是 gsb/batch50-py-safety-c-03 的 repo_trust_arbiter.py，类 RepoTrustArbiter，负责源登记、密钥环隔离、Release 校验、候选排序与降级拦截。现场对账的要求很直白：每个可安装版本都要能追溯到一个当时有效的源，密钥、suite、组件三者对不上就不能进入候选；同样的输入必须解析出同样的顺序，换台机器跑出来也得一样。

公开接口：RepoTrustArbiter(*, installed_versions=None, arch="amd64")、add_key(key_id, material)、revoke_key(key_id)、add_source(source_id, *, origin, suite, components=(), priority=100, keys=())、remove_source(source_id)、publish_package(source_id, *, name, version, component, origin=None, suite=None, arch="amd64", digest="")、verify_release(source_id, *, suite, origin, valid_until, now, key_id, signature)、pin(package, *, source_id, priority, reason="")、unpin(package, *, source_id)、mark_installed(name, version)、candidates(name, *, now=None)、resolve(name, *, now=None, allow_downgrade=False)、status(source_id=None)、audit(*, now=None)、snapshot()、restore(state)、stats()。Release 签名口径是 sha256("origin:suite:valid_until:key_material") 的十六进制。candidates 返回 Candidate(name, version, source_id, priority, suite)，resolve 返回 ResolveResult(name, version, source_id, priority, action)，verify_release 返回含 source_id、suite、origin、valid_until、key_id、state 的字典，拒绝统一抛 RepoError(code)。

故障与边界：①add_source 先查重名再校验密钥绑定，重名报 REPO_SOURCE_DUPLICATE，未登记密钥报 REPO_KEY_UNKNOWN，一钥绑二源报 REPO_KEY_ALREADY_BOUND，任何一步失败都不得留下半个源；②源状态只有 unverified、usable、expired 三种，未验证或已过期的源不进候选；③verify_release 的 key 必须属于该源，否则 REPO_KEY_NOT_BOUND，签名不符报 REPO_RELEASE_SIGNATURE_INVALID 且源保持 unverified，valid_until 不晚于 now 报 REPO_RELEASE_EXPIRED 并把源置为 expired；④包只能发到源登记的 components 内，否则 REPO_COMPONENT_UNKNOWN，同源同名同版本重复发布报 REPO_PACKAGE_DUPLICATE；⑤候选按有效优先级降序、版本降序排列，pin 命中时用 pin 优先级覆盖源优先级；⑥resolve 无候选报 REPO_NO_CANDIDATE，最优候选低于已装版本报 REPO_DOWNGRADE_REFUSED，只有 allow_downgrade 才返回 action=downgrade，等于已装版本返回 keep，高于返回 install；⑦版本按数字段逐段比数值，"1.9" 必须小于 "1.10"；⑧remove_source 要同时解绑密钥、清掉该源的 pin 与包记录，之后这把密钥可以绑到新源；⑨包记录的 Origin 或 Suite 与源登记不一致时，即使签名有效也不得计入候选；⑩pin 优先级相同时按版本比较决定先后，而不是按源添加顺序；⑪status 单源查询给出 source_id、origin、suite、components、priority、keys、state、valid_until、packages，未知源返回 None；audit 给出 sources_total、usable、unverified、expired、packages、keys、pins；⑫snapshot 与 restore 必须深拷贝，结构非法时报 REPO_SNAPSHOT_INVALID 且原状态不变。

硬约束：源增删、密钥绑定、pin 变更与候选计算在同一把锁内完成，校验失败时已有状态一个字节都不能改，并发登记同一把密钥只能成功一次；快照恢复后候选顺序、pin 优先级与降级判断必须与恢复前完全一致，计数器随快照保留。stats 固定给出 keys_added、sources_added、sources_removed、packages_indexed、verified、resolved、downgrades_refused。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；快照恢复与并发场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-03
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: repo_trust_arbiter
- typeName: RepoTrustArbiter
- topic: 软件源信任裁决：按源隔离密钥环、pin 优先级与降级来源拦截
