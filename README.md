# batch50-py-game-a-09-p5

## 题面

合服之后，角色名的争议一下冲到客服前台。玩家用全角拼音注册了「Ａｌｉｃｅ」，另一个人用半角「alice」照样注册成功，两个人站在同一个主城里互相对喷；还有人发现自己名字里的字母大小写，在登录后被改成了别人确认过的写法。第二拨工单是预占：玩家在捏脸界面占了个名字，超时没点确认，隔天点回来居然还能确认成功，一个名字被他白占了两个星期。第三拨是改名：有人改完名当晚，旧名字就被陌生小号抢走，本人想把名字改回去，反而提示已被占用。范围是 gsb/batch50-py-game-a-09-p5 的 character_name_registry.py，类 CharacterNameRegistry，负责角色名与公会名的归一化判重、预占令牌、保留期与改名冷却。

公开接口：CharacterNameRegistry(*, token_ttl=300, rename_cooldown=86400, max_tokens_per_owner=3, max_name_length=16, min_name_length=2, banned_words=None, reserved_words=None)；normalize(name)、reserve(name, owner, *, now=None)、confirm(token, *, display_name=None, now=None)、release(token, owner)、rename(owner, new_name, *, now=None)、lookup(name)、expire(now=None)、owner_names(owner)、snapshot()、restore(state)、stats()。拒绝一律抛 NameRegistryError(code, detail)。

故障与边界：①归一化顺序固定为 NFKC 全半角折叠、casefold 大小写折叠、去首尾空白、连续空白压成一个半角空格，空串或非字符串报 NAME_INVALID；②名字只允许字母、数字、空格、下划线、连字符，长度从 min_name_length 到 max_name_length，超长报 NAME_TOO_LONG，其余不合规报 NAME_INVALID；③归一化后命中禁用词报 NAME_BANNED，命中保留词报 NAME_RESERVED；④同一个归一化键只能有一份生效占用，已确认、预占中、冷却中的键都不能再被他人预占，统一报 NAME_TAKEN；⑤令牌按 n000001 起递增，预占返回 name、key、owner 与 expires_at，每个占用者同时持有的未确认令牌不超过 max_tokens_per_owner，超限报 NAME_CAPACITY_EXCEEDED；⑥confirm 把令牌转成正式记录，display_name 归一化后必须与预占键一致否则报 NAME_INVALID，令牌不存在报 NAME_TOKEN_UNKNOWN，确认成功后令牌立即作废，重复确认按不存在处理；⑦release 只接受令牌持有人，占用者不匹配报 NAME_OWNER_MISMATCH，释放后名字立即回到可用状态；⑧expire 只清理超时的未确认令牌并返回条数，已确认记录永不因为时间过期；⑨rename 要求占用者已有确认名，否则报 NAME_OWNER_UNKNOWN，新名与当前键相同报 NAME_UNCHANGED，新名已被占用报 NAME_TAKEN，成功后返回 previous_key 与 cooldown_until；⑩lookup 按归一化键返回确认记录，没有确认记录时返回 None，owner_names 返回该占用者的全部确认名并按显示名升序；⑪两个不同码位序列归一化后相同应视为同名冲突，但显示名保留首次确认的写法，后续等价写法不得覆盖；⑫预占过期后原占用者再次确认必须失败，令牌不可复活；改名释放旧名后进入冷却期，冷却内他人不可占用但本人可回滚。

硬约束：reserve、confirm、release、rename、expire 共用一把锁，多线程同时预占同一个名字只能有一个成功，其余必须报 NAME_TAKEN，令牌序号不得重复也不得跳号；快照固定为 version、tokens、names、cooldowns、stats 五个键，深拷贝，restore 校验版本与结构，缺键或类型不对报 NAME_SNAPSHOT_INVALID 且现场不动，恢复后预占、确认记录、冷却与计数继续可用，重启不能让已确认的名字回到未占用；令牌数量、名字长度与名字总量都有硬上限，lookup 必须是归一化键上的直接命中，不得遍历全表比对。

验收：python3 -m pytest -q tests 的 15 条用例必须全过，不许改测试、不许跳过、不许按固定输入写死；并发与重启恢复自行验证；只做本地实现，不引入第三方库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: character_name_registry
- typeName: CharacterNameRegistry
