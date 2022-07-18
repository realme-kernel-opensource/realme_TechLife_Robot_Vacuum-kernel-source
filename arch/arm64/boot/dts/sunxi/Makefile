dtb-$(CONFIG_ARCH_SUN50IW3P1) += board.dtb

dtb-$(CONFIG_ARCH_SUN50IW1P1) += sun50iw1p1-fpga.dtb  sun50iw1p1-perf1_v1_0.dtb \
				sun50iw1p1-perf2_v1_0.dtb sun50iw1p1-t1.dtb \
				sun50iw1p1-sata.dtb sun50iw1p1-soc.dtb

dtb-$(CONFIG_ARCH_SUN50IW6P1) += board.dtb

dtb-$(CONFIG_ARCH_SUN50IW8P1) += sun50iw8p1-fpga.dtb sun50iw8p1-soc.dtb
dtb-$(CONFIG_ARCH_SUN50IW9P1) += sun50iw9p1-fpga.dtb
dtb-$(CONFIG_ARCH_SUN50IW5T) += sun50iw5t-fpga.dtb

always		:= $(dtb-y)
subdir-y	:= $(dts-dirs)
clean-files	:= *.dtb
