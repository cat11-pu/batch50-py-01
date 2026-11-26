# batch50-py-safety-c-01-p2

## 题面

运维值班这周被资源上限连着打了三次脸。周一批量构建把 nofile 调到 65535，任务跑完机器一重启全部掉回 1024，容器里一路报 too many open files，构建失败率直接顶到三成；周三有人在生产机上把 stack 的硬限从 8M 抬到 64M，理由是"临时排查"，当晚一个递归解析把栈打穿，整台机器跟着卡死，事后没人说得清是谁改的；周五的回退脚本按名字顺序摘绑定，摘掉的不是最后加上的那条，中间两层 profile 一直挂着，新上线的服务跟着吃紧，值班同学谁也不敢再动。范围是 gsb/batch50-py-safety-c-01-p2 的 rlimit_profile_switcher.py，类 RlimitProfileSwitcher，负责命名 profile 的登记、按进程绑定的栈式应用与回退、进程身份核对，以及重启后的绑定重挂。

公开接口：RlimitProfileSwitcher(*, max_profiles=32, max_frames_per_pid=8)；define_profile(name, limits) 返回 ProfileSpec(name, limits)；remove_profile(name)；apply_profile(pid, name, *, tenant=None)；bind_pid(pid, name, *, start_time, tenant=None)；rollback_last(pid, *, steps=1)；effective_limits(pid)；profile_of(pid)；frames(pid) 返回 Frame(profile, tenant) 元组；register_process(pid, start_time)；inherit(parent_pid, child_pid, *, start_time)；save(path)；load(path) 返回 reattached 与 stale 两个计数；snapshot()、restore(state)、stats()。拒绝统一抛 RlimitError(code, detail)。

故障与边界：①limits 的键只能是 nofile、nproc、stack，值形如 (soft, hard)，允许 None 表示沿用当前值；非整数、负数、布尔、三元组、软高于硬、空表一律 PROFILE_INVALID；②重名报 PROFILE_EXISTS，超过 max_profiles 报 PROFILE_CAPACITY；③目标硬限高于当前硬限必须拒绝 HARD_RAISE_REFUSED，普通路径只能单调收紧，进程现有上限一点不能动，被拒后栈和生效表都不许变；④解析后的软限高于硬限报 SOFT_ABOVE_HARD，例如只想把硬限压到 512 却没同时压低原来的软限 1024；⑤生效表按字典序返回且是副本，profile 没写的键沿用当前生效值；snapshot 返回 schema、profiles、processes、bases、frames、stats 六个键且深拷贝，restore 缺键或类型不符报 SNAPSHOT_INVALID 且原状态不变；⑥回退严格 LIFO，rollback_last 返回被摘下的 profile 名元组，可一次摘多帧，栈空返回空元组；⑦每进程栈帧受 max_frames_per_pid 约束，超限报 FRAME_CAPACITY，未登记的 profile 报 PROFILE_UNKNOWN；⑧同一进程重复绑定同一 profile 只压入一个栈帧，回退一次之后该 profile 仍应生效；⑨重启后按落盘的 pid 加启动时间核对进程身份，pid 被新进程复用时不得把旧绑定挂到新进程上，这类帧计入 stale，不得计入 reattached；⑩写盘先落临时文件再原子替换，文件顶层为 schema、profiles、processes、bases、frames、stats，processes 以 pid 字符串为键存启动时间，frames 下每个 pid 按 [profile, tenant] 两元组自底向上排列，内容损坏、文件缺失或版本不符报 STATE_INVALID 且内存状态不变；⑪仍被绑定的 profile 不许删除，报 PROFILE_IN_USE；⑫子进程继承父进程当时的生效上限快照，之后父进程回退不影响子进程，父进程不存在报 PID_UNKNOWN。

硬约束：多个线程同时对同一 pid 绑定不同 profile 时必须串行化，帧不能丢也不能串，applied 与实际帧数要对得上，任何一次拒绝都不能留下半截栈帧；落盘与重启恢复要保证帧顺序和生效上限一致，恢复后已挂接的帧不得重复计数，恢复失败也不许把内存里的绑定清掉。stats 固定返回 profiles、applied、denied、frames_popped、stale_bindings、saves、loads 七个键，saves 与 loads 只统计成功的调用，denied 只统计 apply 与 bind 被拒的次数。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与重启场景自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-01-p2
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: rlimit_profile_switcher
- typeName: RlimitProfileSwitcher
- file: rlimit_profile_switcher.py
