# batch50-py-safety-d-26

## 题面

财务共享盘的目录加密这周连出三起事故。一是某个子目录被人单独设成了另一把密钥，父目录的策略管不到它，备份任务按父策略解密时整批文件报错；二是一个运维在下发密钥轮换后中途离场，回来发现一半文件用新密钥打不开、一半还是旧密钥，谁也说不出哪些已经转完；三是值班同学反馈，目录处于锁定状态时点开文件返回的是空白内容，业务侧误判成文件被清空，直接触发了数据丢失告警。范围是 gsb/batch50-py-safety-d-26 的 fscrypt_policy_warden.py，类名 FscryptPolicyWarden，负责目录策略的继承与收窄、密钥槽管理、锁定解锁以及密钥轮换的中断续跑。

公开接口：FscryptPolicyWarden(*, volume="v1", max_policies=16, key_slots=6)；mkdir(path)；register_file(path, name, size=4096)；set_policy(path, *, mode, key_desc, policy_id=None, recursive=False) -> PolicyRecord；unlock(path, key_desc) -> int；lock(path) -> int；read_file(path, name) -> str；write_file(path, name, data="") -> str；file_key(path, name) -> str；rotate(path, new_key_desc, *, interrupt_after=None) -> dict；resume_rotation(path) -> dict；add_key(key_desc, *, policy_id) -> int；drop_key(key_desc, *, policy_id) -> int；keys()；policies()；status(path)；rename(old, new)；snapshot()；restore(state)；stats()。拒绝时统一抛 FscryptError(code, detail)。

故障与边界：①路径必须是以 / 开头的规范绝对路径，重复建目录报 FSCRYPT_EXISTS，目录不存在报 FSCRYPT_NO_DIR；②模式只认 aes128-cts、aes256-cts、aes256-xts，其它值在改动任何状态之前就报 FSCRYPT_UNSUPPORTED_MODE；③非空目录首次设置策略必须带 recursive=True，否则报 FSCRYPT_DIR_NOT_EMPTY，递归只覆盖尚无策略的后代目录；④子目录默认继承最近的祖先策略，显式 policy_id 与祖先不一致报 FSCRYPT_POLICY_MISMATCH，key_desc 不同报 FSCRYPT_KEY_MISMATCH，模式只能同强度或更强，变弱报 FSCRYPT_MODE_WIDEN；⑤每卷已设策略的目录数超过 max_policies 报 FSCRYPT_POLICY_LIMIT，未给标识时按创建顺序生成 pol-1、pol-2，policies() 按路径升序，返回的记录含 path、policy_id、mode、key_desc、key_state、rotation_state、rotation_pending；⑥unlock 要求该策略标识下已登记对应密钥，否则报 FSCRYPT_KEY_UNAVAILABLE 且状态不变，成功返回解锁的目录数并覆盖子树；⑦lock 返回锁定目录数；read_file 返回写入内容，write_file 返回本次使用的密钥描述，file_key 返回该文件的密钥描述；锁定后读写都报 FSCRYPT_LOCKED，不得返回空串；无策略报 FSCRYPT_NO_POLICY，文件名缺失报 FSCRYPT_NOT_FOUND；status 含 path、policy_id、mode、key_desc、key_state、rotation_state、rotation_pending 与 files；⑧rotate 要求目标目录已解锁且已有策略，否则分别报 FSCRYPT_LOCKED、FSCRYPT_NO_POLICY；轮换先登记新密钥，再按文件名升序逐文件重加密，全部完成才移除旧密钥；返回含 old_key_desc、new_key_desc、total、pending、state 的进度，中断后 state 为 partial，未转完的文件仍用旧密钥可读；轮换中再次发起报 FSCRYPT_ROTATION_BUSY，新旧密钥相同报 FSCRYPT_BAD_ROTATION；⑨密钥槽满报 FSCRYPT_KEY_SLOT_EXHAUSTED，重复登记报 FSCRYPT_KEY_EXISTS，删除在用密钥报 FSCRYPT_KEY_IN_USE，add_key 与 drop_key 返回当前占用槽数，设置策略本身不占密钥槽、密钥必须显式登记，keys() 返回按策略标识与密钥描述升序的二元组；⑩目录在加密状态下被 rename 到另一父目录，策略必须跟着目录本身走，不能按新路径重新继承；⑪轮换进行中新写入的文件必须直接落到新密钥，不能先写旧密钥再排队等重加密；⑫解锁时同一 key_desc 在多个策略下都登记过，必须按目标目录的策略标识精确选取，不能取第一个匹配项。

硬约束：同一目录上的 set_policy、unlock、lock、rotate 必须串行，轮换进度与密钥槽变更不得交错；快照必须是深拷贝，保存策略表、密钥槽与轮换进度，恢复后锁定状态和部分轮换的已完成文件数原样回来，非法快照报 FSCRYPT_SNAPSHOT_INVALID 且现有数据不动。stats 返回 policies、dirs、files、unlocked、rotations_done、rotations_partial、denied，其中 policies 是已设策略的目录数、dirs 是已建目录数。

验收：python3 -m pytest -q tests 的 15 条必须全过，不得修改测试、跳过用例或按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: fscrypt_policy_warden
- typeName: FscryptPolicyWarden
