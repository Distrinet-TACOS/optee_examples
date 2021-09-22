# If KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq ($(KERNELRELEASE),)
obj-m := console-split.o
# Otherwise we were called directly from the command
# line; invoke the kernel build system.
else
PWD := $(shell pwd)
KERNELDIR ?= $(PWD)/../../linux

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) CROS_COMPLIE="ccache arm-linux-gnueabihf-" ARCH=arm LOCALVERSION= modules
endif

clean:
	rm -rf .*.cmd *.ko *.mod* *.o modules* Module*