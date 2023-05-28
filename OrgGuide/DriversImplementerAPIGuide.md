# 驱动开发人员API指南（Driver implementer's API guide）

内核（kernel）为设备驱动开发提供了丰富的接口。这个文档只涵盖此类接口中的一部分呢。

## 驱动模型
### 驱动绑定

驱动绑定（driver binding）指的是使设备和能控制它的驱动发生关联的过程（process of associating）。

#### 总线（bus）

总线类型结构体（bus type structure）包含一个系统中挂在此类中线上的所有设备的链表（list）。当设备调用设备寄存器（device_register）的时候，它就会插到这个这个链表的末尾。总线结构体还包含一个所有与此类总线相关联的驱动的链表，当驱动调用设备寄存器时，就会插入这个驱动链表。

上述两种调用就是触发驱动绑定的两类事件（event）。

#### 设备寄存器（device_register）

当有新的设备添加到系统中的时候，系统会在总线的驱动列表中查找与之适配的驱动。为了支持上述操作，设备的device ID必须与某个驱动支持的device ID之一匹配。

这种匹配过程是与总线相关的（bus-specific）——依赖总线提供的原型如下的回调函数（callback）提供匹配结果。

```c
int match(struct device * dev, struct device_driver * drv);
```

假如匹配成功，那么设备的驱动域（driver field）就会设置为匹配到的驱动。驱动的验证回调（probe callback）也会被调用，用以确认驱动驱动处于工作状态（working state）、并且确实能驱动这个硬件。

#### 设备类（device class）

假如验证回调（probe callback）顺利返回，那么设备就被注册到所属的唯一的设备类（device class）啦。和驱动写道设备的驱动域一样，设备类会写到设备的设备类域（devclass field）。

此过程将调用```devclass_add_device```将设备实际注册到它所属的设备类中（注册是通过调用```register_dev```）完成的。

#### 驱动（driver）

当驱动和设备关联后（attached to a device），设备会插入驱动的设备链表中。

#### sysfs

在总线的```devices```目录下创建一个指向设备目录的符号链接（symlink）。

在驱动的```devices```目录下创建一个指向设备目录的符号链接（symlink）。

在设备类的目录下创建一个设备目录，在这个目录中创建一个指向设备目录的符号链接。

#### 驱动寄存器（driver_register）

当系统中新增驱动时，系统会在总线的设备链表中为之尽可能多地匹配没有驱动的设备（跳过已经有驱动的设备）。

#### Removal

设备从系统中移除时，他的引用计数会被清零。移除回调（remove callback）会被调用。设备会从驱动的设备链表中移除，驱动的引用计数递减。驱动和设备之间的所有符号链接都会被移除。

驱动从系统中移除时，设备链表中所有设备的移除回调（remove callback）被依次调用，设备从该链表中移除，符号链接也被移除。

