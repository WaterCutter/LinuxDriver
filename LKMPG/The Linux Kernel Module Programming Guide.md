# The Linux Kernel Module Programming Guide
- Peter Jay Salzman, Michael Burian, Ori Pomerantz, Bob Mottram, Jim Huang
- 译 断水客（WaterCutter）

## 5 预备知识（Preliminaries）

### 5.1 模块的入口函数和出口函数

C 程序通常从 `main()` 函数开始执行一系列指令，执行完成后退出。模块有所不同，它们通常从 `module_init()` 或者开发者用 `module_init` 指定（specified）的函数开始执行。这个函数即模块的入口函数（entry function），它告诉内核该模块提供的功能、建立模块运行需要的环境。`module_init()` 执行完退出后，模块将等待内核的请求，否则不会有任何动作。

模块终止前执行 `module_exit()` 或者开发者用 `module_exit` 指定的函数，即所谓出口函数（exit function）。这个函数用于撤销（undo）入口函数的行为，注销（unregister）入口函数注册的功能。

这两个函数是模块必须具备的，铁打不动。

### 5.2 模块可用的函数

模块是依赖于 `insmod` 或者 `modprobe` 解析的符号的 object 文件。所以模块中调用的外部函数（external function）限定于内核支持的那些系统调用（system call）。内核支持的系统调用可以在 `/proc/kallsyms` 文件中查看。

类似于 `printf()` 这种 C 标准库 libc 中的函数，是建立在系统调用 `write()` 之上的抽象用户接口。在模块中如果想输出到 stdout，只能使用 `write()`来代替 `printf()` 。  

内核的系统调用可以通过模块替换，黑客经常将这种手段做后门或木马。

### 5.3 用户空间和内核空间

常说用户程序跑在用户空间，内核运行在内核空间，但要理解内核和用户程序的本质区别，还是得明确划分用户空间和内核空间的本因。

内核就是对资源访问的控制（A kernel is all about access to resources）， 用户程序总是在竞争使用磁盘、内存、声卡、显卡等资源，内核的任务就是有条不紊地将这些资源分配给用户程序。

要保证内核顺利完成工作，就需要约束用户程序地访问权限，让用户程序不能随意访问资源，一切资源的访问都通过内核进行。这种需求反映在 CPU 设计中，就体现为多种特权模式，比如 x86 中的多种 ring 。

此等意义上，就可以把系统调用理解为用户API接口在内核空间的代表，代表用户程序实现对资源的访问。通常，在用户模式下使用库函数，将会调用一个或多个系统调用，这些系统调用代表库函数执行，但在特权模式下执行此操作，因为它们是内核本身的一部分。系统调用完成其任务后，它将返回并执行将传输回用户模式。

### 5.4 命名空间

当一个程序有很多全局变量，这些变量命名不清晰/不规范，造成区分问题时，就会造成命名空间污染（namespace pollution）。

即使是最小的模块也会与整个内核链接，最好将所有变量声明为静态变量，并为符号使用定义良好的前缀。如果不想将所有内容声明为静态，可以声明符号表并将其注册到内核。

`/proc/kallsyms` 文件中的所有符号与模块共享代码空间（code space），也就意味着编写模块时不能再声明包含在这个文件中的符号。

### 5.5 代码空间

O’Reilly 的 《[Understanding The Linux Kernel](https://www.oreilly.com/library/view/understanding-the-linux/0596005652/)》 中有专门的章节介绍 Linux 的内存管理（memory managment）。

每个应用程序和内核都有自己的内存空间。由于模块共享内核的代码空间，而不是像应用程序一样独有代码空间。因此，如果模块出现段错误，则内核就会出现段错误。所以写模块时应该时刻小心。

### 5.6 设备驱动

有些模块是设备驱动，为串口（serial port）这种硬件设备提供支持。

Unix 中，每个硬件都由 `/dev` 目录下的某个设备文件代表。比如 '/dev/sound' 代表声卡，如果声卡硬件es1370，那么用户程序访问 '/dev/sound' 时，系统就会通过 es1370.ko 模块与声卡交互，应用程序无需关心到底是什么型号的声卡。

让我们看一些设备文件。以下是代表主主IDE硬盘驱动器上的前三个分区的设备文件：

```bash
$ ls -l /dev/hda[1-3]
brw-rw----  1 root  disk  3, 1 Jul  5  2000 /dev/hda1
brw-rw----  1 root  disk  3, 2 Jul  5  2000 /dev/hda2
brw-rw----  1 root  disk  3, 3 Jul  5  2000 /dev/hda3
```

请注意用逗号分隔的数字列。第一个数字称为设备的主设备号，第二个数字是次设备号。主设备号标明使用哪个驱动程序访问硬件。每个驱动程序都分配有一个唯一的主编号，具有相同主编号的所有设备文件都由同一驱动程序控制。以上所有主要数字都是 3，因为它们都由同一个驱动程序控制。

驱动程序使用次设备号来区分它控制的各种硬件。回到上面的示例，尽管所有三个设备都由同一驱动程序处理，但它们具有唯一的次设备号，因为驱动程序将它们视为不同的硬件。

设备分为两种类型：字符设备和块设备。不同之处在于块设备具有请求缓冲区，因此它们可以选择响应请求的最佳顺序。这在存储设备的情况下很重要，在存储设备中，读取或写入彼此靠近的扇区比那些相距较远的扇区更快。另一个区别是块设备只能接受块中的输入和返回输出（其大小可以根据设备而变化），而字符设备可以使用任意数量的字节。世界上大多数设备都是字符，因为它们不需要这种类型的缓冲，并且它们不以固定的块大小运行。您可以通过查看 `ls -l` 输出中的第一个字符来判断设备文件是用于块设备还是字符设备。如果它是“b”，那么它是一个块设备，如果它是“c”，那么它是一个字符设备。您在上面看到的设备是块设备。以下是一些字符设备（串行端口）：

```bash
crw-rw----  1 root  dial 4, 64 Feb 18 23:34 /dev/ttyS0
crw-r-----  1 root  dial 4, 65 Nov 17 10:26 /dev/ttyS1
crw-rw----  1 root  dial 4, 66 Jul  5  2000 /dev/ttyS2
crw-rw----  1 root  dial 4, 67 Jul  5  2000 /dev/ttyS3
```
如果要查看已分配的主要编号，可以查看：[Documentation/admin-guide/devices.txt.](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/admin-guide/devices.txt)

安装系统时，所有这些设备文件都是由 `mknod` 命令创建的。要创建一个名为 coffee 的新字符设备，主要/次要编号为 12 和 2，只需执行 `mknod /dev/coffee c 12 2` 。您不必将设备文件放入 `/dev` 中，但这是按照惯例完成的。Linus 将他的设备文件放在 `/dev` 中，你也应该如此。但是，在创建用于测试目的的设备文件时，可能可以将其放在编译内核模块的工作目录中。只需确保在编写完设备驱动程序后将其放在正确的位置即可。

## 6 字符设备驱动

[include/linux/fs.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/fs.h) 中定义了结构体 `file_operations` ，这个结构体包含指向再设备上执行各种操作的系列函数。结构体的每一字段都对应着驱动中定义的处理请求的函数的地址。


> 所谓“每一字段对应驱动中...的函数的地址”，即是说 `file_operations` 中包含一系列的函数指针，指向模块中具体的函数实现。可以把这个结构体理解为设备的操作清单，编写驱动时只需要根据实际需要实现清单中的部分接口就行了。


```c
struct file_operations { 
    struct module *owner; 
    loff_t (*llseek) (struct file *, loff_t, int); 
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *); 
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *); 
    ssize_t (*read_iter) (struct kiocb *, struct iov_iter *); 
    ssize_t (*write_iter) (struct kiocb *, struct iov_iter *); 
    int (*iopoll)(struct kiocb *kiocb, bool spin); 
    int (*iterate) (struct file *, struct dir_context *); 
    int (*iterate_shared) (struct file *, struct dir_context *); 
    __poll_t (*poll) (struct file *, struct poll_table_struct *); 
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long); 
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long); 
    int (*mmap) (struct file *, struct vm_area_struct *); 
    unsigned long mmap_supported_flags; 
    int (*open) (struct inode *, struct file *); 
    int (*flush) (struct file *, fl_owner_t id); 
    int (*release) (struct inode *, struct file *); 
    int (*fsync) (struct file *, loff_t, loff_t, int datasync); 
    int (*fasync) (int, struct file *, int); 
    int (*lock) (struct file *, int, struct file_lock *); 
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int); 
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long); 
    int (*check_flags)(int); 
    int (*flock) (struct file *, int, struct file_lock *); 
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int); 
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int); 
    int (*setlease)(struct file *, long, struct file_lock **, void **); 
    long (*fallocate)(struct file *file, int mode, loff_t offset, 
        loff_t len); 
    void (*show_fdinfo)(struct seq_file *m, struct file *f); 
    ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, 
        loff_t, size_t, unsigned int); 
    loff_t (*remap_file_range)(struct file *file_in, loff_t pos_in, 
             struct file *file_out, loff_t pos_out, 
             loff_t len, unsigned int remap_flags); 
    int (*fadvise)(struct file *, loff_t, loff_t, int); 
} __randomize_layout;
```

某些操作不会在驱动中实现（implemeted by a driver）。例如声卡驱动不需要实现从目录结构中读取的接口，那么这个驱动提供的 `file_operations` 结构体中的相关指针就可以设为 `NULL`。

GCC 扩展（gcc extension）支持便捷的结构体初始化方式（即内核中常用的乱序初始化），用法形如：

```c
struct file_operations fops = { 
    read: device_read, 
    write: device_write, 
    open: device_open, 
    release: device_release 
};
```

或者使用 C99 风格的 [designed initilizers](https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html) 初始化结构体。


`file_operations` 中包含的用于实现read、write等系统调用的函数，通常被称为 `fops`。

从 3.14 版内核开始， read、write、seek等操作`fops` 就已经有线程安全的（thread-safe）特定锁（specific lock）保护了，这使得文件位置更新（file position update）是互斥的（mutual exclusion）。所以我们在实现这些操作的时候不需要类似目的的锁（unnecessary locking）。

> 在计算机中，文件位置更新是指将文件指针移动到文件中的特定位置。

此外，从 5.6 版开始，开发者向内核引入了 `proc_ops` 结构体，在注册 proc handlers 时不在使用 `file_operations` 结构体。

> 在计算机操作系统中，进程处理程序（proc handlers）是一种用于处理进程中断和异常的机制。主要作用是保证进程的正常运行和安全性。当进程发生中断或异常时，进程处理程序可以采取适当的措施来处理这些事件，例如重新启动进程、恢复进程状态、记录日志等。

### 6.2 File 结构体

每个设备在内核中都由一个 `struct file` 结构体表示，这个结构体定义在文件 [include/linux/fs.h.](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/fs.h)中。

这个结构体不是用户程序常用的 glibc 中定义的 `FILE`。另外这个结构体的命名有些误导作用，它指的是抽象的打开的文件，而非用 `inode` 指代的磁盘文件。

`struct file` 的指针（instance）通常被称为 `filp`。

驱动基本不会使用[include/linux/fs.h.](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/fs.h) 中定义的各类接口直接覆写（fill） `struct file` ，只会调用 `struct file` 中包含的各结构体。

### 6.3 注册设备

如前所述，用户一般是通过 `/dev` 目录下的设备文件（device files）访问字符设备的。

主设备号标明驱动处理哪个设备文件，次设备号只用于有多个设备时，驱动分辨正在使用的设备（which device is operating on）。

向系统中添加一个设备意味着将这个设备注册到内核中。在模块初始化的时候会通过调用定义在 `include/linux/fs.h` 中的 `register_chrdev()` 函数为设备分配一个主设备号，其原型如下：

```c
int register_chrdev(unsigned int major, const char *name, struct file_operations *fops);
```

`major` 是主设备号，`name` 是可以在文件 `/proc/devices` 中看到的设备名，`*fops` 指向驱动中 file_operations 表的指针。函数返回负数表明设备注册失败。值得一提的是，这个函数不涉及次设备号，因为只有驱动才使用这个属性，内核并不关心次设备号。

现在问题来了，如何才能获取一个没被使用的主设备号呢？最简单的方式是查看 [Documentation/admin-guide/devices.txt](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/admin-guide/devices.txt) 然后选一个没有被占用的设备号。但这不是一个好办法，因为这个方法无法操作的互斥性，不能保证后续不会有其他设备使用同样的设备号。正确的答案是向内核请求一个动态的主设备号（ask the kernel to assign you a dynamic major number）。

向函数 `register_chrdev()` 传参数 0 ，它的返回值就是 `dynamic major number`。这个办法的弊端在于，因为不确定设备注册时会获得哪个动态设备号，也就不能提前创建设备文件。又三种解决方案：

1. 驱动打印输出主设备号，然后手动创建设备文件
2. 新注册的设别会显示在 `/proc/devices` 文件中，可以通过读这个文件获取主设备号，然后手动/脚本创建设备文件
3. 驱动在成功注册设备后，通过 `device_create()` 函数创建设备文件，并在 `cleanup_module()` 函数中调用函数 `device_destroy()`。

不过，`register_chrdev()` 函数会占用一些和主设备号相关的次设备号，推荐使用 cdev interface 注册字符设备以减少对次设备号的浪费。

使用 cdev interface 注册字符设备分两步走。

第一步，调用 `register_chrdev_region()` 或者  `alloc_chrdev_region()` 注册一系列设备号（register a range of device numbers）。

```c
int register_chrdev_region(dev_t from, unsigned count, const char *name); 
int alloc_chrdev_region(dev_t *dev, unsigned baseminor, unsigned count, const char *name);
```

如果指定设备号，使用 `register_chrdev_region()`，否则使用 `alloc_chrdev_region()`。

第二步，使用下面的方法为字符设备初始化结构体 `struct cdev`，并将它和第一步注册的 device number 关联起来（associate it with the device numbers）。

```c
struct cdev *my_dev = cdev_alloc(); 
my_cdev->ops = &my_fops;
```

上面是 `cdev` 单独存在的情况，更常规的情况是，设备驱动的 `fops` 中包含这个结构体，那就要用到 `cdev_init()` 函数了，原型如下：

```c
void cdev_init(struct cdev *cdev, const struct file_operations *fops);
```

完成初始化后，可用 `cdev_add()` 函数将字符设备添加到系统中，函数原型如下：

```c
int cdev_add(struct cdev *p, dev_t dev, unsigned count);
```

上述各种用法，可以在第 9 章提到的`ioctl.c`中找到使用范例。

### 6.4 注销（unregistering）设备

即使拥有 root 权限，也不能随意使用 rmmod 命令（allow module to be rmmoded whenever root feels like）。假设在某个进程大打开了设备文件的情况下注销对应的模块，对设备文件的操作将会导致不可预知的后果——运气好的话（模块原在的位置没有重装其他代码），会收到一个错误信息；运气不好的话（重装了其他代码），那就会导致意料之外的操作被执行，这肯定不是什么好事（they can not be very positive）。

使用 `cat /proc/modules` 或者 `sudo lsmod .` 命令可以在回显信息的第 3 栏看到各模块被多少个进程使用。如果对应值不为 0，`rmmod` 将失败。注意编写模块时不必在 `cleanup_module` 里检查这个计数值，因为定义在 [include/linux/syscalls.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/module.h) 中的系统调用 `sys_delete_module` 会干这个事。咱可以使用下面几个定义在 [include/linux/module.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/module.h) 中的函数增减和查询这个计数器的值：

- try_module_get(THIS_MODULE) : Increment the reference count of current module.
- module_put(THIS_MODULE) : Decrement the reference count of current module.
- module_refcount(THIS_MODULE) : Return the value of reference count of current module.

必须严格保证上述计数器的准确性，否则会导致模块永远无法被卸载（即使没有后进程使用，计数器也不为0， `rmmod` 一直失败）。

### 6.5 chardev.c

下面是一个创建字符设备的例程，这个例子不适用于多核环境中各核对共享内存的操作，关于 `atomic Compare-And-Swap (CAS) to maintain the states, CDEV_NOT_USED and CDEV_EXCLUSIVE_OPEN` 的讨论将在第 12 章中进行。

```c
/* 
 * chardev.c: Creates a read-only char device that says how many times 
 * you have read from the dev file 
 */ 
 
#include <linux/atomic.h> 
#include <linux/cdev.h> 
#include <linux/delay.h> 
#include <linux/device.h> 
#include <linux/fs.h> 
#include <linux/init.h> 
#include <linux/kernel.h> /* for sprintf() */ 
#include <linux/module.h> 
#include <linux/printk.h> 
#include <linux/types.h> 
#include <linux/uaccess.h> /* for get_user and put_user */ 
 
#include <asm/errno.h> 
 
/*  Prototypes - this would normally go in a .h file */ 
static int device_open(struct inode *, struct file *); 
static int device_release(struct inode *, struct file *); 
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *); 
static ssize_t device_write(struct file *, const char __user *, size_t, 
                            loff_t *); 
 
#define SUCCESS 0 
#define DEVICE_NAME "chardev" /* Dev name as it appears in /proc/devices   */ 
#define BUF_LEN 80 /* Max length of the message from the device */ 
 
/* Global variables are declared as static, so are global within the file. */ 
 
static int major; /* major number assigned to our device driver */ 
 
enum { 
    CDEV_NOT_USED = 0, 
    CDEV_EXCLUSIVE_OPEN = 1, 
}; 
 
/* Is device open? Used to prevent multiple access to device */ 
static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED); 
 
static char msg[BUF_LEN + 1]; /* The msg the device will give when asked */ 
 
static struct class *cls; 
 
static struct file_operations chardev_fops = { 
    .read = device_read, 
    .write = device_write, 
    .open = device_open, 
    .release = device_release, 
}; 
 
static int __init chardev_init(void) 
{ 
    major = register_chrdev(0, DEVICE_NAME, &chardev_fops); 
 
    if (major < 0) { 
        pr_alert("Registering char device failed with %d\n", major); 
        return major; 
    } 
 
    pr_info("I was assigned major number %d.\n", major); 
 
    cls = class_create(THIS_MODULE, DEVICE_NAME); 
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME); 
 
    pr_info("Device created on /dev/%s\n", DEVICE_NAME); 
 
    return SUCCESS; 
} 
 
static void __exit chardev_exit(void) 
{ 
    device_destroy(cls, MKDEV(major, 0)); 
    class_destroy(cls); 
 
    /* Unregister the device */ 
    unregister_chrdev(major, DEVICE_NAME); 
} 
 
/* Methods */ 
 
/* Called when a process tries to open the device file, like 
 * "sudo cat /dev/chardev" 
 */ 
static int device_open(struct inode *inode, struct file *file) 
{ 
    static int counter = 0; 
 
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN)) 
        return -EBUSY; 
 
    sprintf(msg, "I already told you %d times Hello world!\n", counter++); 
    try_module_get(THIS_MODULE); 
 
    return SUCCESS; 
} 
 
/* Called when a process closes the device file. */ 
static int device_release(struct inode *inode, struct file *file) 
{ 
    /* We're now ready for our next caller */ 
    atomic_set(&already_open, CDEV_NOT_USED); 
 
    /* Decrement the usage count, or else once you opened the file, you will 
     * never get rid of the module. 
     */ 
    module_put(THIS_MODULE); 
 
    return SUCCESS; 
} 
 
/* Called when a process, which already opened the dev file, attempts to 
 * read from it. 
 */ 
static ssize_t device_read(struct file *filp, /* see include/linux/fs.h   */ 
                           char __user *buffer, /* buffer to fill with data */ 
                           size_t length, /* length of the buffer     */ 
                           loff_t *offset) 
{ 
    /* Number of bytes actually written to the buffer */ 
    int bytes_read = 0; 
    const char *msg_ptr = msg; 
 
    if (!*(msg_ptr + *offset)) { /* we are at the end of message */ 
        *offset = 0; /* reset the offset */ 
        return 0; /* signify end of file */ 
    } 
 
    msg_ptr += *offset; 
 
    /* Actually put the data into the buffer */ 
    while (length && *msg_ptr) { 
        /* The buffer is in the user data segment, not the kernel 
         * segment so "*" assignment won't work.  We have to use 
         * put_user which copies data from the kernel data segment to 
         * the user data segment. 
         */ 
        put_user(*(msg_ptr++), buffer++); 
        length--; 
        bytes_read++; 
    } 
 
    *offset += bytes_read; 
 
    /* Most read functions return the number of bytes put into the buffer. */ 
    return bytes_read; 
} 
 
/* Called when a process writes to dev file: echo "hi" > /dev/hello */ 
static ssize_t device_write(struct file *filp, const char __user *buff, 
                            size_t len, loff_t *off) 
{ 
    pr_alert("Sorry, this operation is not supported.\n"); 
    return -EINVAL; 
} 
 
module_init(chardev_init); 
module_exit(chardev_exit); 
 
MODULE_LICENSE("GPL");

```

### 6.6 为不同版本的内核编写模块

系统调用是内核暴露给进程的主要接口，通常在内核迭代过程中保持稳定，只增不减（old ones will behave exactly like they used to）。类似于向后兼容（back compatibility），切换为新的内核通常不必修改设备驱动。另一方面，内核的内部接口（非暴露给进程的）可以并且确实在版本之间发生变更（can and do change between versions）。

> The way to do this to compare the macro LINUX_VERSION_CODE to the macro KERNEL_VERSION . In version a.b.c of the kernel, the value of this macro would be 2^16×a + 28×b + c.

## 7 /proc 文件系统

Linux 中有一个额外的机制——/proc file system，用于支持内核和模块向进程（processes）发送信息。

这个机制最设计为访问进程信息，现在用于内核报告（used by every bit of the kernel which has something interesting to report）,这些报告包括提供模块列表的 `/proc/modules` 文件、收集内存使用情况的 `/proc/meminfo` 文件。

/proc 文件系统的用法与设备驱动类似——创建一个包含 /proc 文件信息和多个句柄函数（handler function）的指针的结构体，使用 `init_module` 注册，使用 `cleanup_module` 注销。

常规的（normal）文件系统在磁盘（disk）上，而 /proc 在内存（memory）中，`inode number` 是一个指向文件在磁盘上的位置的指针。`inode` 中包含文件的权限、指向文件数据在磁盘中的位置的指针。

因为此类文件在被打开或者关闭时不会收到调用，开发者也就无处调用 `try_module_get()` 和 `module_put()` （见第 6 章对这两个函数的说明）, 这也意味着文件打开时模块可以被移除。

下面是一个使用 /proc 文件的例程，包含初始化函数 `init_module()`、返回一个值和 buffer 的读取函数 `procfile_read()` 以及删除文件 `/proc/helloworld` 的函数 `cleanup_module()`。

模块被函数 `proc_create()` 加载时将创建文件 `/proc/helloworld`。类型为 `struct proc_dir_entry` 的返回值将被用于配置文件 `/proc/helloworld` ，返回值为 `NULL` 则意味着创建文件失败。

每当文件 `proc/helloworld` 被读取时，函数 `procfile_read()` 就会被调用。这个函数的第二个参数 `buffer` 和第四个参数 `offset` 十分重要。 `buffer` 的内容将被传递给读取该文件的应用程序（例如 cat 命令）， `offset` 则标记文件当前的读取位置。如果该函数的返回值不为 `NULL` ，则将被不停地调用（called endlessly）。

> $ cat /proc/helloworld
HelloWorld!

```c
/* 
 * procfs1.c 
 */ 
 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/proc_fs.h> 
#include <linux/uaccess.h> 
#include <linux/version.h> 
 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0) 
#define HAVE_PROC_OPS 
#endif 
 
#define procfs_name "helloworld" 
 
static struct proc_dir_entry *our_proc_file; 
 
static ssize_t procfile_read(struct file *file_pointer, char __user *buffer, 
                             size_t buffer_length, loff_t *offset) 
{ 
    char s[13] = "HelloWorld!\n"; 
    int len = sizeof(s); 
    ssize_t ret = len; 
 
    if (*offset >= len || copy_to_user(buffer, s, len)) { 
        pr_info("copy_to_user failed\n"); 
        ret = 0; 
    } else { 
        pr_info("procfile read %s\n", file_pointer->f_path.dentry->d_name.name); 
        *offset += len; 
    } 
 
    return ret; 
} 
 
#ifdef HAVE_PROC_OPS 
static const struct proc_ops proc_file_fops = { 
    .proc_read = procfile_read, 
}; 
#else 
static const struct file_operations proc_file_fops = { 
    .read = procfile_read, 
}; 
#endif 
 
static int __init procfs1_init(void) 
{ 
    our_proc_file = proc_create(procfs_name, 0644, NULL, &proc_file_fops); 
    if (NULL == our_proc_file) { 
        proc_remove(our_proc_file); 
        pr_alert("Error:Could not initialize /proc/%s\n", procfs_name); 
        return -ENOMEM; 
    } 
 
    pr_info("/proc/%s created\n", procfs_name); 
    return 0; 
} 
 
static void __exit procfs1_exit(void) 
{ 
    proc_remove(our_proc_file); 
    pr_info("/proc/%s removed\n", procfs_name); 
} 
 
module_init(procfs1_init); 
module_exit(procfs1_exit); 
 
MODULE_LICENSE("GPL");
```

### 7.1 proc_ops 结构体

proc_ops 结构体定义在 5.6 及更高版本 Linux 内核的 [ include/linux/proc_fs.h ](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/proc_fs.h) 文件中。旧版本内核使用  file_operations /proc 文件系统的用户钩子（user hooks）。但它包含一些在 VFS 中不必要的成员，并且每次 VFS 扩展 file_operations 集时，/proc 代码都会变得臃肿。除此之外，proc_ops 结构不仅节省了空间，还节省了一些操作以提高其性能。例如，在 /proc 中永远不会消失的文件可以将proc_flag设置为PROC_ENTRY_PERMANENT，以在每个 open/read/close 序列中省去 2 个原子操作、1 个allocation、1 个free 。

### 7.2 读写 /proc 文件

7.1 节中展示了一个简单的 /proc 文件读取操作，这里我们尝试写入 /proc 文件。二者非常类似，但写 /proc 的数据来自于用户，所以咱需要用 `copy_from_user` 或者 `get_user` 把数据从用户空间（user space）导入（import）到内核空间（kernel space）。

> The reason for copy_from_user or get_user is that Linux memory (on Intel architecture, it may be different under some other processors) is segmented. This means that a pointer, by itself, does not reference a unique location in memory, only a location in a memory segment, and you need to know which memory segment it is to be able to use it. There is one memory segment for the kernel, and one for each of the processes.

> The only memory segment accessible to a process is its own, so when writing regular programs to run as processes, there is no need to worry about segments. When you write a kernel module, normally you want to access the kernel memory segment, which is handled automatically by the system. However, when the content of a memory buffer needs to be passed between the currently running process and the kernel, the kernel function receives a pointer to the memory buffer which is in the process segment. The put_user and get_user macros allow you to access that memory. These functions handle only one character, you can handle several characters with copy_to_user and copy_from_user . As the buffer (in read or write function) is in kernel space, for write function you need to import data because it comes from user space, but not for the read function because data is already in kernel space.

```c
/* 
 * procfs2.c -  create a "file" in /proc 
 */ 
 
#include <linux/kernel.h> /* We're doing kernel work */ 
#include <linux/module.h> /* Specifically, a module */ 
#include <linux/proc_fs.h> /* Necessary because we use the proc fs */ 
#include <linux/uaccess.h> /* for copy_from_user */ 
#include <linux/version.h> 
 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0) 
#define HAVE_PROC_OPS 
#endif 
 
#define PROCFS_MAX_SIZE 1024 
#define PROCFS_NAME "buffer1k" 
 
/* This structure hold information about the /proc file */ 
static struct proc_dir_entry *our_proc_file; 
 
/* The buffer used to store character for this module */ 
static char procfs_buffer[PROCFS_MAX_SIZE]; 
 
/* The size of the buffer */ 
static unsigned long procfs_buffer_size = 0; 
 
/* This function is called then the /proc file is read */ 
static ssize_t procfile_read(struct file *file_pointer, char __user *buffer, 
                             size_t buffer_length, loff_t *offset) 
{ 
    char s[13] = "HelloWorld!\n"; 
    int len = sizeof(s); 
    ssize_t ret = len; 
 
    if (*offset >= len || copy_to_user(buffer, s, len)) { 
        pr_info("copy_to_user failed\n"); 
        ret = 0; 
    } else { 
        pr_info("procfile read %s\n", file_pointer->f_path.dentry->d_name.name); 
        *offset += len; 
    } 
 
    return ret; 
} 
 
/* This function is called with the /proc file is written. */ 
static ssize_t procfile_write(struct file *file, const char __user *buff, 
                              size_t len, loff_t *off) 
{ 
    procfs_buffer_size = len; 
    if (procfs_buffer_size > PROCFS_MAX_SIZE) 
        procfs_buffer_size = PROCFS_MAX_SIZE; 
 
    if (copy_from_user(procfs_buffer, buff, procfs_buffer_size)) 
        return -EFAULT; 
 
    procfs_buffer[procfs_buffer_size & (PROCFS_MAX_SIZE - 1)] = '\0'; 
    *off += procfs_buffer_size; 
    pr_info("procfile write %s\n", procfs_buffer); 
 
    return procfs_buffer_size; 
} 
 
#ifdef HAVE_PROC_OPS 
static const struct proc_ops proc_file_fops = { 
    .proc_read = procfile_read, 
    .proc_write = procfile_write, 
}; 
#else 
static const struct file_operations proc_file_fops = { 
    .read = procfile_read, 
    .write = procfile_write, 
}; 
#endif 
 
static int __init procfs2_init(void) 
{ 
    our_proc_file = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops); 
    if (NULL == our_proc_file) { 
        proc_remove(our_proc_file); 
        pr_alert("Error:Could not initialize /proc/%s\n", PROCFS_NAME); 
        return -ENOMEM; 
    } 
 
    pr_info("/proc/%s created\n", PROCFS_NAME); 
    return 0; 
} 
 
static void __exit procfs2_exit(void) 
{ 
    proc_remove(our_proc_file); 
    pr_info("/proc/%s removed\n", PROCFS_NAME); 
} 
 
module_init(procfs2_init); 
module_exit(procfs2_exit); 
 
MODULE_LICENSE("GPL");
```
### 7.3 用标准文件系统管理 /proc 文件

咱已知晓如何使用 /proc 接口读写 /proc文件，但是否有可能使用 `inode
` 管理 /proc 文件呢？ 问题聚焦于一些高级功能（advance function）——譬如权限管理。

Linux 中有一套标准的文件注册机制，每个文件系统都有处理 `inode` 和文件操作的函数，也有一些内含这些函数的指针的结构体—— `struct inode_operations`, 这个结构体中包含一个指向 `struct proc_ops` 的指针。

文件操作（file operations）和 `inode` 操作的（inode operations）区别在于，前者处理文件本身，而后者处理文件索引相关的事情——比如创建文件链接（create links to it）。

这里要提到另一个有趣的东西—— `module_permission` 函数。这个函数在进程尝试操作 /proc 文件时被调用，决定是否允许相应的操作。目前允许与否仅取决于当前用户的 `uid`, 但实际可以取决于其他进程对该文件的操作、日期、或者收到的信息等我们指定的任意判据。

需要注意到内核中的读写是方向颠倒的，使用 read 函数写，用 write 函数读。因为读写是从用户的视角描述的，当用户需要从内核读取数据时，内核应当输出对应的数据。

> It is important to note that the standard roles of read and write are reversed in the kernel. Read functions are used for output, whereas write functions are used for input. The reason for that is that read and write refer to the user’s point of view — if a process reads something from the kernel, then the kernel needs to output it, and if a process writes something to the kernel, then the kernel receives it as input.

```c
/* 
 * procfs3.c 
 */ 
 
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/proc_fs.h> 
#include <linux/sched.h> 
#include <linux/uaccess.h> 
#include <linux/version.h> 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0) 
#include <linux/minmax.h> 
#endif 
 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0) 
#define HAVE_PROC_OPS 
#endif 
 
#define PROCFS_MAX_SIZE 2048UL 
#define PROCFS_ENTRY_FILENAME "buffer2k" 
 
static struct proc_dir_entry *our_proc_file; 
static char procfs_buffer[PROCFS_MAX_SIZE]; 
static unsigned long procfs_buffer_size = 0; 
 
static ssize_t procfs_read(struct file *filp, char __user *buffer, 
                           size_t length, loff_t *offset) 
{ 
    if (*offset || procfs_buffer_size == 0) { 
        pr_debug("procfs_read: END\n"); 
        *offset = 0; 
        return 0; 
    } 
    procfs_buffer_size = min(procfs_buffer_size, length); 
    if (copy_to_user(buffer, procfs_buffer, procfs_buffer_size)) 
        return -EFAULT; 
    *offset += procfs_buffer_size; 
 
    pr_debug("procfs_read: read %lu bytes\n", procfs_buffer_size); 
    return procfs_buffer_size; 
} 
static ssize_t procfs_write(struct file *file, const char __user *buffer, 
                            size_t len, loff_t *off) 
{ 
    procfs_buffer_size = min(PROCFS_MAX_SIZE, len); 
    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) 
        return -EFAULT; 
    *off += procfs_buffer_size; 
 
    pr_debug("procfs_write: write %lu bytes\n", procfs_buffer_size); 
    return procfs_buffer_size; 
} 
static int procfs_open(struct inode *inode, struct file *file) 
{ 
    try_module_get(THIS_MODULE); 
    return 0; 
} 
static int procfs_close(struct inode *inode, struct file *file) 
{ 
    module_put(THIS_MODULE); 
    return 0; 
} 
 
#ifdef HAVE_PROC_OPS 
static struct proc_ops file_ops_4_our_proc_file = { 
    .proc_read = procfs_read, 
    .proc_write = procfs_write, 
    .proc_open = procfs_open, 
    .proc_release = procfs_close, 
}; 
#else 
static const struct file_operations file_ops_4_our_proc_file = { 
    .read = procfs_read, 
    .write = procfs_write, 
    .open = procfs_open, 
    .release = procfs_close, 
}; 
#endif 
 
static int __init procfs3_init(void) 
{ 
    our_proc_file = proc_create(PROCFS_ENTRY_FILENAME, 0644, NULL, 
                                &file_ops_4_our_proc_file); 
    if (our_proc_file == NULL) { 
        remove_proc_entry(PROCFS_ENTRY_FILENAME, NULL); 
        pr_debug("Error: Could not initialize /proc/%s\n", 
                 PROCFS_ENTRY_FILENAME); 
        return -ENOMEM; 
    } 
    proc_set_size(our_proc_file, 80); 
    proc_set_user(our_proc_file, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID); 
 
    pr_debug("/proc/%s created\n", PROCFS_ENTRY_FILENAME); 
    return 0; 
} 
 
static void __exit procfs3_exit(void) 
{ 
    remove_proc_entry(PROCFS_ENTRY_FILENAME, NULL); 
    pr_debug("/proc/%s removed\n", PROCFS_ENTRY_FILENAME); 
} 
 
module_init(procfs3_init); 
module_exit(procfs3_exit); 
 
MODULE_LICENSE("GPL");
```

仍觉得例程不够丰富？有传言称procfs即将被淘汰，建议考虑使用sysfs代替。如果想自己记录一些与内核相关的内容，再考虑使用这种机制。

> Consider using this mechanism, in case you want to document something kernel related yourself.