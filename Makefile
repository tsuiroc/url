EXTRA_CFLAGS += -D__LINUX_KERNEL__
EXTRA_CFLAGS += -I./
EXTRA_CFLAGS +=  -Wno-format-extra-args -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function
EXTRA_CFLAGS += -Wno-format -Wno-return-type -Wno-strict-prototypes -Wno-unused -Wno-implicit

url-objs := main.o url_hook.o
obj-m := url.o
KERNEL_DIR :=/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	@echo "Build Module URL"
	@make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean 