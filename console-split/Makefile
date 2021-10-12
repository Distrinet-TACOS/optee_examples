# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
KBUILD_EXTRA_SYMBOLS += $(PWD)/../split-driver-controller/Module.symvers

obj-m := console-split.o
ccflags-y := -I$(src)/../split-driver-controller
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
PWD := $(shell pwd)
KERNELDIR ?= $(PWD)/../../linux
KBUILD_EXTRA_SYMBOLS += $(PWD)/../split-driver-controller/Module.symvers

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CROSS_COMPLIE="ccache arm-linux-gnueabihf-" ARCH=arm LOCALVERSION= modules
endif

clean:
	rm -rf .*.cmd *.ko *.mod* *.o modules* Module*
