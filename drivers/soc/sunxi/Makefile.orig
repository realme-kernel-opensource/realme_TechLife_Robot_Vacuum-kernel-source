obj-$(CONFIG_SUNXI_SRAM) +=	sunxi_sram.o
obj-y +=        sunxi-sid.o

ifneq ($(strip $(CONFIG_ARCH_SUN8IW8P1)),)
obj-$(CONFIG_PM) += pm/
obj-$(CONFIG_SCENELOCK)     +=  pm/scenelock/scenelock.o
obj-$(CONFIG_USER_SCENELOCK) += pm/scenelock/userscenelock.o
else
obj-$(CONFIG_PM) += pm.o
endif
obj-y += arisc/
