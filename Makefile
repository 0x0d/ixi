obj-m += ixi.o
ixi-objs := base.o utils.o vfs.o sct.o net.o rc4.o
CC = gcc

EXTRA_CFLAGS = -Wall
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	@echo
	@echo "----------------------------------------------------"
	@echo " IXI by INVENT"
	@echo " invent@0x0a.net | http://0x0a.net/"
	@echo "----------------------------------------------------"
	@echo
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

