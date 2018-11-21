# 使用kprobes获取sys_execve参数
## 测试环境：
```
root@localhost:~/test# lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04 LTS
Release:	18.04
Codename:	bionic
root@localhost:~/test# uname -r
4.15.0-34-generic

```
## 起因：
在上述测试环境下，安装yulong发现驱动未加载，然后手动加载驱动发现如下错误：
![1.jpg](https://github.com/lovewinxp/kprobes_hook/blob/master/jpg/1.png)

接着使用dmesg查看相关信息，发现如下错误：
![1.jpg](https://github.com/lovewinxp/kprobes_hook/blob/master/jpg/2.png)

后来找了很多相关资料，发现jprobes在4.15以后被移除了（[这里](https://stackoverflow.com/questions/13438328/why-do-i-get-38-error-while-trying-to-insmod-a-kernel-module-probing-do-fork "这里")），自己通过如下命令印证了这个说法：
![1.jpg](https://github.com/lovewinxp/kprobes_hook/blob/master/jpg/3.png)

从上图中可以看出kprobe还存在，我们知道kprobe也是可以完成类似效果，所以打算使用kprobe来代替jprobes。

## 修改：
从[这篇文章](http://ssdxiao.github.io/linux/2015/12/10/kprobe-example.html "这篇文章")中得知pt_regs结构体存储了函数调用中的寄存器的值，具体di、si、dx、cx分别对应函数调用的前四个参数。pt_regs结构体（/usr/src/linux-headers-4.15.0-34-generic/arch/x86/include/asm/ptrace.h）如下：
```c
struct pt_regs {
	/*
	 * NB: 32-bit x86 CPUs are inconsistent as what happens in the
	 * following cases (where %seg represents a segment register):
	 *
	 * - pushl %seg: some do a 16-bit write and leave the high
	 *   bits alone
	 * - movl %seg, [mem]: some do a 16-bit write despite the movl
	 * - IDT entry: some (e.g. 486) will leave the high bits of CS
	 *   and (if applicable) SS undefined.
	 *
	 * Fortunately, x86-32 doesn't read the high bits on POP or IRET,
	 * so we can just treat all of the segment registers as 16-bit
	 * values.
	 */
	unsigned long bx;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long bp;
	unsigned long ax;
	unsigned short ds;
	unsigned short __dsh;
	unsigned short es;
	unsigned short __esh;
	unsigned short fs;
	unsigned short __fsh;
	unsigned short gs;
	unsigned short __gsh;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned short cs;
	unsigned short __csh;
	unsigned long flags;
	unsigned long sp;
	unsigned short ss;
	unsigned short __ssh;
};

```
而sys_execve（/usr/src/linux-headers-4.15.0-34-generic/include/linux/syscalls.h）的原型如下：
```c
asmlinkage long sys_execve(const char __user *filename,
                const char __user *const __user *argv,
                const char __user *const __user *envp);
```
可以看到有3个参数，所以需要用到di、si、dx，这三个分别对应：
- di：文件路径
- si：命令行参数
- dx：环境变量


最后修改完成后，手动加载驱动进行测试：
```bash
insmod syshook_execve.ko
```
## 改造后运行效果：
![1.jpg](https://github.com/lovewinxp/kprobes_hook/blob/master/jpg/4.png)
