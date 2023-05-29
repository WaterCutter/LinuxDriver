# The Linux Kernel Module Programming Guide
- Peter Jay Salzman, Michael Burian, Ori Pomerantz, Bob Mottram, Jim Huang


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

# 6 字符设备驱动

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