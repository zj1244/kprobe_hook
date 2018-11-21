obj-m := syshook_execve.o

KERNEL := /lib/modules/`uname -r`/build

all:
		make -C $(KERNEL)   M=`pwd` modules

install:
		make -C $(KERNEL)   M=`pwd` modules_install
			depmod -A

clean:
		make -C $(KERNEL)   M=`pwd` clean
