ifeq ($(KBUILD_TOP),)
    ifneq ($(KBUILD_EXTMOD),)
    KBUILD_DIR := $(KBUILD_EXTMOD)
    else
    KBUILD_DIR := $(PWD)
    endif
KBUILD_TOP := $(KBUILD_DIR)/../
endif

include $(KBUILD_TOP)/config.mak


KBUILD_EXTRA_SYMBOLS += $(KBUILD_TOP)/ssvdevice/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(KBUILD_TOP)/hci/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(KBUILD_TOP)/prealloc/Module.symvers

KMODULE_NAME=ssv6200s_core
KERN_SRCS := init.c
KERN_SRCS += dev.c
KERN_SRCS += regd.c
KERN_SRCS += wow.c
KERN_SRCS += hw_scan.c

KERN_SRCS += lib.c
KERN_SRCS += ap.c

ifeq ($(findstring -DCONFIG_SSV6XXX_DEBUGFS, $(ccflags-y)), -DCONFIG_SSV6XXX_DEBUGFS)
KERN_SRCS += ssv6xxx_debugfs.c
endif

KERN_SRCS += efuse.c
KERN_SRCS += p2p.c
KERN_SRCS += ssv_skb.c
ifeq ($(findstring -DCONFIG_SMARTLINK, $(ccflags-y)), -DCONFIG_SMARTLINK)
KERN_SRCS += ksmartlink.c
ifeq ($(findstring -DCONFIG_SSV_SMARTLINK, $(ccflags-y)), -DCONFIG_SSV_SMARTLINK)
KERN_SRCS += kssvsmart.c
endif
endif

KERN_SRCS += hal/hal.c
ifeq ($(findstring -DSSV_SUPPORT_SSV6006, $(ccflags-y)), -DSSV_SUPPORT_SSV6006)
KERN_SRCS += hal/ssv6006c/ssv6006_common.c
KERN_SRCS += hal/ssv6006c/ssv6006C_mac.c
KERN_SRCS += hal/ssv6006c/ssv6006_phy.c
KERN_SRCS += hal/ssv6006c/ssv6006_turismoC.c
ifeq ($(findstring -DSSV_SUPPORT_SSV6006AB, $(ccflags-y)), -DSSV_SUPPORT_SSV6006AB)
KERN_SRCS += hal/ssv6006/ssv6006_mac.c
KERN_SRCS += hal/ssv6006/ssv6006_cabrioA.c
KERN_SRCS += hal/ssv6006/ssv6006_geminiA.c
KERN_SRCS += hal/ssv6006/ssv6006_turismoA.c
KERN_SRCS += hal/ssv6006/ssv6006_turismoB.c
endif
endif

include $(KBUILD_TOP)/rules.mak
