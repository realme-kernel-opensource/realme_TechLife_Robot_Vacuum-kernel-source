CONFIG_SSV6X5X=m
#ccflags-y += -DCONFIG_SSV6200_CORE
CONFIG_MAC80211_LEDS=y
CONFIG_MAC80211_DEBUGFS=y
CONFIG_MAC80211_MESH=y
CONFIG_PM=y
CONFIG_MAC80211_RC_MINSTREL=y
CONFIG_MAC80211_RC_MINSTREL_HT=y

//ccflags-y += -D_ICOMM_MAC80211_

ccflags-y += -D__CHECK_ENDIAN__ -DDEBUG
###########################################################################
# Compiler options                                                        #
###########################################################################
ccflags-y += -Werror

# Enable -g to help debug. Deassembly from .o to .S would help to track to 
# the problomatic line from call stack dump.
#ccflags-y += -g

#########################################################
# option enable shal
ccflags-y += -DSSV_SUPPORT_SSV6006

############################################################
# If you change the settings, please change the file synchronization
# smac\firmware\include\config.h & compiler firmware
############################################################
#ccflags-y += -DSDIO_USE_SLOW_CLOCK

#CONFIG_SSV_SUPPORT_BTCX=y

ccflags-y += -DCONFIG_SSV6200_CLI_ENABLE

#ccflags-y += -DCONFIG_SSV_BUILD_AS_ONE_KO


############################################################
# Options should be able to set as parameters.             #
############################################################

#ccflags-y += -DCONFIG_SSV6XXX_HW_DEBUG
#SDIO
ccflags-y += -DCONFIG_SSV_TX_LOWTHRESHOLD

############################################################
# Rate control update for MPDU.
############################################################
ccflags-y += -DRATE_CONTROL_REALTIME_UPDATE

# FOR WFA
#ccflags-y += -DWIFI_CERTIFIED

#ccflags-y += -DCONFIG_SSV_SDIO_EXT_INT

#######################################################
ccflags-y += -DCONFIG_SSV6200_HAS_RX_WORKQUEUE
ccflags-y += -DUSE_THREAD_RX
ccflags-y += -DUSE_THREAD_TX
ccflags-y += -DENABLE_AGGREGATE_IN_TIME
ccflags-y += -DENABLE_INCREMENTAL_AGGREGATION

# Generic decision table applicable to both AP and STA modes.
ccflags-y += -DUSE_GENERIC_DECI_TBL

########################################################
## The following definition move to indivdual platform
## should not enable again here. 

#ccflags-y += -DCONFIG_SSV6XXX_DEBUGFS
#### end of move to individual platform

ccflags-y += -DSSV6200_ECO
#ccflags-y += -DENABLE_WAKE_IO_ISR_WHEN_HCI_ENQUEUE

#enable per skb throughput profiling
#ccflags-y += -DCONFIG_THROUGHPUT_PROFILE

#enable p2p client to parse GO broadcast noa
#ccflags-y += -DCONFIG_P2P_NOA

#enable rx management frame check
#ccflags-y += -DCONFIG_RX_MGMT_CHECK

#enable smart icomm

#ccflags-y += -DCONFIG_SMARTLINK
#ccflags-y += -DCONFIG_SSV_SMARTLINK

ccflags-y += -DCONFIG_SSV_CCI_IMPROVEMENT

#enable USB LPM function
#ccflags-y += -DSSV_SUPPORT_USB_LPM

# Don't use stack for sdio_memcpy_xxx()
#ccflags-y += -DCONFIG_MMC_DISALLOW_STACK

#enable skb prealloc
#ccflags-y += -DCONFIG_PREALLOC_TRX_BIG_SKB

# Collect Rx data skb and process in tasklet to achive TCP Delay ACK.
#ccflags-y += -DSMAC_RX_TASKLET

# Process HWIF SDIO Rx interrupt directly in function which is called by kernel, instead of work queue.
ccflags-y += -DHWIF_SDIO_RX_IRQ

# Filter out beacon and probe request while STA connected (NOT for concurrence mode)
ccflags-y += -DCONFIG_STA_BCN_FILTER
ccflags-y += -DCONFIG_SSV_USE_SDIO_DAT1_AS_INT

# Skip Tx while there is SDIO interrupt status has Rx
ccflags-y += -DCONFIG_SDIO_FAVOR_RX

# SDIO safe read/write register
ccflags-y += -DHWIF_IGNORE_SAFE_RW_REG

# support hw scan
ccflags-y += -DCONFIG_HW_SCAN

# support USB multi tx urb
ccflags-y += -DCONFIG_USB_TX_MULTI_URB

ccflags-y += -DCONFIG_USB_EP0_RW_REGISTER

