# batch50-py-safety-c-04

## 题面

桌面运维这周被投诉了三次：会议室的扩展坞插上后键盘被自动放行，同一个扩展坞换个口再插又弹一次授权；有人把同型号的 U 盘插到另一个口上，系统直接沿用了上一台的授权；还有一台设备的临时授权到期后，文件传输进程仍握着句柄继续读写。安全组复核发现，复合设备只要有一个接口被禁就该整体拒绝，可现场只按 VID/PID 判了允许。取证时还发现，同一台设备热插拔十几次，台账里躺着十几条有效授权，谁也说不清哪条才对应真机。范围是 gsb/batch50-py-safety-c-04 的 usb_device_authorizer.py，类 UsbDeviceAuthorizer，负责插入事件评估、规则匹配、设备指纹、临时授权与句柄回收。

公开接口：UsbDeviceAuthorizer(*, temp_window=300, rules=None)、add_rule(rule_id, *, vid, pid=None, serial=None, interfaces=(), decision="allow", ttl=None)、remove_rule(rule_id)、on_insert(*, vid, pid, interfaces, port_path, serial=None, now=None)、evaluate(fingerprint)、authorize(fingerprint, *, ttl=None, now=None)、revoke(fingerprint, *, now=None)、expire(*, now=None)、attach(fingerprint, handle_id)、detach(handle_id)、handles(fingerprint)、devices()、status()、snapshot()、restore(state)、stats()。on_insert 返回 DeviceRecord(fingerprint, vid, pid, serial, interfaces, port_path, state, expires_at, matched_rule, prompt)，expire 返回 ExpireReport(revoked, handles_closed)，evaluate 返回该指纹当前状态串、未知指纹返回 None，拒绝统一抛 UsbError(code)。

故障与边界：①设备状态只有 pending、authorized、temp、denied、revoked、expired；未知设备首次插入置 pending 且 prompt=True，重复插入同一指纹只回一条记录、prompt=False，并计入 deduped；②规则按 vid、可选 pid、可选 serial 与接口集匹配，带 serial 的规则优先于只带 vid/pid 的规则，同分时 deny 压过 allow；③allow 规则的接口集必须覆盖设备全部接口才生效，deny 规则只要命中任一接口就整体拒绝，设备接口去重后按字典序保存在记录里；④指纹：有序列号时只由 VID、PID 与序列号决定，换口不变；无序列号时必须结合端口路径，不能只按 VID/PID 归并；⑤authorize 传 ttl 时状态为 temp、expires_at 为 now 加 ttl 秒且格式与 now 一致，不传 ttl 为 authorized 且 expires_at=None，到期判定按同格式 UTC 时间字符串先后比较即可；⑥expire 只处理到期的 temp，返回撤销数与关闭句柄数，状态转 expired；⑦revoke 关闭该设备全部句柄并返回关闭数，重复 revoke 返回 0 且计数不涨，已撤销设备再次插入保持 revoked 且不再弹窗；⑧attach 只允许 authorized 与 temp，其他状态报 USB_NOT_AUTHORIZED，重复 handle_id 报 USB_HANDLE_DUPLICATE；⑨已授权设备换成同型号但接口类不同的另一台时不得沿用旧授权；⑩临时授权窗口内拔出再插入不得刷新 expires_at；⑪快照深拷贝，恢复后已授权设备再次插入不弹窗，结构非法报 USB_SNAPSHOT_INVALID 且原状态不变；⑫status 给出 devices、authorized、temp、pending、denied、revoked、expired、handles、rules，stats 固定给出 inserts、deduped、prompts、authorized、denied、revoked、expired、handles_opened。

硬约束：插入评估、授权变更、句柄登记与到期回收在同一把锁内完成，同一指纹并发插入只能产生一条记录、prompt 只能记一次，也不得重复登记句柄或提前触发到期；快照恢复后设备状态、句柄、规则与八个计数器全部一致，重复恢复不得叠加计数。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发插入与重启恢复自行构造验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch50-py-safety-c-04
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: usb_device_authorizer
- typeName: UsbDeviceAuthorizer
- topic: USB 设备授权：复合设备接口级规则、无序列号归并与临时授权窗口
