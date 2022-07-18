#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <ssv6200.h>
#include "../smac/lib.h"
#include "../smac/dev.h"
#include "kssvsmart.h"
#include <hal.h>
#include "dev.h"
#include "init.h"

#ifdef CONFIG_SMARTLINK

//#define SSV_SMARTLINK_DEBUG
#define GLOBAL_NL_ID 999

enum {
    KSMARTLINK_ATTR_UNSPEC,
    KSMARTLINK_ATTR_ENABLE,
    KSMARTLINK_ATTR_SUCCESS,
    KSMARTLINK_ATTR_CHANNEL,
    KSMARTLINK_ATTR_PROMISC,
    KSMARTLINK_ATTR_RXFRAME,
    KSMARTLINK_ATTR_SI_CMD,
    KSMARTLINK_ATTR_SI_STATUS,
    KSMARTLINK_ATTR_SI_SSID,
    KSMARTLINK_ATTR_SI_PASS,
    __KSMARTLINK_ATTR_MAX,
};
#define KSMARTLINK_ATTR_MAX (__KSMARTLINK_ATTR_MAX - 1)

static struct nla_policy ksmartlink_genl_policy[KSMARTLINK_ATTR_MAX + 1] = {
    [KSMARTLINK_ATTR_ENABLE]        = { .type = NLA_U32 },
    [KSMARTLINK_ATTR_SUCCESS]       = { .type = NLA_U32 },
    [KSMARTLINK_ATTR_CHANNEL]       = { .type = NLA_U32 },
    [KSMARTLINK_ATTR_PROMISC]       = { .type = NLA_U32 },
    [KSMARTLINK_ATTR_RXFRAME]       = { .type = NLA_BINARY, .len = IEEE80211_MAX_DATA_LEN },
    [KSMARTLINK_ATTR_SI_CMD]        = { .type = NLA_U32 },
    [KSMARTLINK_ATTR_SI_STATUS]     = { .type = NLA_STRING },
    [KSMARTLINK_ATTR_SI_SSID]       = { .type = NLA_STRING },
    [KSMARTLINK_ATTR_SI_PASS]       = { .type = NLA_STRING },
};

enum {
    KSMARTLINK_CMD_UNSPEC,
    KSMARTLINK_CMD_SMARTLINK,
    KSMARTLINK_CMD_SET_CHANNEL,
    KSMARTLINK_CMD_GET_CHANNEL,
    KSMARTLINK_CMD_SET_PROMISC,
    KSMARTLINK_CMD_GET_PROMISC,
    KSMARTLINK_CMD_RX_FRAME,
    KSMARTLINK_CMD_SMARTICOMM,
    KSMARTLINK_CMD_SET_SI_CMD,
    KSMARTLINK_CMD_GET_SI_STATUS,
    KSMARTLINK_CMD_GET_SI_SSID,
    KSMARTLINK_CMD_GET_SI_PASS,
    __KSMARTLINK_CMD_MAX,
};
#define KSMARTLINK_CMD_MAX (__KSMARTLINK_CMD_MAX - 1)

static struct genl_family ksmartlink_gnl_family;

int ksmartlink_cmd_smartlink(struct sk_buff *skb, struct genl_info *info)
{
    u32 enable;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);

    if (info == NULL)
        return -EINVAL;

    if (!info->attrs[KSMARTLINK_ATTR_ENABLE])
    {
        printk("the attrs is not enable\n");
        return -EINVAL;
    }
    else 
    {
        enable = nla_get_u32(info->attrs[KSMARTLINK_ATTR_ENABLE]);
#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_cmd_smartlink enable=%d\n", enable);
#endif
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
    ssv_smartlink_sc->ssv_usr_pid = info->snd_portid;
#else
    ssv_smartlink_sc->ssv_usr_pid = info->snd_pid;
#endif

    /* TODO */
    ssv_smartlink_sc->ssv_smartlink_status = enable;


    return 0;

}

static int ksmartlink_set_channel(struct sk_buff *skb, struct genl_info *info)
{
    int retval;
    u32 channel;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);
    struct ieee80211_channel chan, *pchan = &chan;

    if (info == NULL)
        return -EINVAL;

    if (!info->attrs[KSMARTLINK_ATTR_CHANNEL])
        return -EINVAL;
    else 
    {
        channel = nla_get_u32(info->attrs[KSMARTLINK_ATTR_CHANNEL]);
#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_set_channel channel=%d\n", channel);
#endif
    }
    /* TODO: set channel */
    memset(&chan, 0 , sizeof( struct ieee80211_channel));
    chan.hw_value = channel;
    
    mutex_lock(&ssv_smartlink_sc->mutex);
    HAL_SET_CHANNEL_CHECK(ssv_smartlink_sc, pchan, NL80211_CHAN_HT20, false, retval);
    mutex_unlock(&ssv_smartlink_sc->mutex);

    return retval;
}

static int ksmartlink_get_channel(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    int retval;
    void *hdr;
    u32 channel = 0x00;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);

    if (info == NULL)
        return -EINVAL;

    /* TODO: get channel */ 
    mutex_lock(&ssv_smartlink_sc->mutex);
    retval = ssv6xxx_get_channel(ssv_smartlink_sc, &channel);
    mutex_unlock(&ssv_smartlink_sc->mutex);

    /* allocate new netlink packet */
    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_get_channel\n");
#endif

    hdr = genlmsg_put(msg, 0, info->snd_seq, &ksmartlink_gnl_family, 0, KSMARTLINK_CMD_GET_CHANNEL);
    if (!hdr)
    {
        retval = -ENOBUFS;
        goto free_msg;
    }
    retval = nla_put_u32(msg, KSMARTLINK_ATTR_CHANNEL, channel);
    if (retval)
    {
        printk("Fail to add attribute in message\n");
        goto free_msg;
    }

    genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

free_msg:
    nlmsg_free(msg);
    return retval;
}

static int ksmartlink_set_promisc(struct sk_buff *skb, struct genl_info *info)
{
    int retval;
    u32 promisc;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);

    if (info == NULL)
        return -EINVAL;

    if (!info->attrs[KSMARTLINK_ATTR_PROMISC])
        return -EINVAL;
    else 
    {
        promisc = nla_get_u32(info->attrs[KSMARTLINK_ATTR_PROMISC]);
#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_set_promisc promisc=%d\n", promisc);
#endif
    }
    /* TODO: set promisc */
    mutex_lock(&ssv_smartlink_sc->mutex);
    retval = ssv6xxx_set_promisc(ssv_smartlink_sc, promisc);
    mutex_unlock(&ssv_smartlink_sc->mutex);

    return retval;
}

static int ksmartlink_get_promisc(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    int retval;
    void *hdr;
    u32 promisc = 0x00;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);

    if (info == NULL)
        return -EINVAL;

    /* TODO: get promisc */
    mutex_lock(&ssv_smartlink_sc->mutex);
    retval = ssv6xxx_get_promisc(ssv_smartlink_sc, &promisc);
    mutex_unlock(&ssv_smartlink_sc->mutex);
    
    /* allocate new netlink packet */
    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_get_promisc\n");
#endif

    hdr = genlmsg_put(msg, 0, info->snd_seq, &ksmartlink_gnl_family, 0, KSMARTLINK_CMD_GET_PROMISC);
    if (!hdr)
    {
        retval = -ENOBUFS;
        goto free_msg;
    }
    retval = nla_put_u32(msg, KSMARTLINK_ATTR_PROMISC, promisc);
    if (retval)
    {
        printk("Fail to add attribute in message\n");
        goto free_msg;
    }

    genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

free_msg:
    nlmsg_free(msg);
    return retval;
}

#ifdef CONFIG_SSV_SMARTLINK

static int ksmartlink_start_smarticomm(struct sk_buff *skb, struct genl_info *info)
{
    u32 enable;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);

    if (info == NULL)
        return -EINVAL;

    if (!info->attrs[KSMARTLINK_ATTR_ENABLE])
        return -EINVAL;
    else 
    {
        enable = nla_get_u32(info->attrs[KSMARTLINK_ATTR_ENABLE]);
#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_start_smarticomm enable=%d\n", enable);
#endif
    }

    ssv_smartlink_sc->ssv_smartlink_status = enable;

    return 0;
}

static int ksmartlink_set_si_cmd(struct sk_buff *skb, struct genl_info *info)
{
    u32 si_cmd;

    if (info == NULL)
        return -EINVAL;

    if (!info->attrs[KSMARTLINK_ATTR_SI_CMD])
        return -EINVAL;
    else 
    {
        si_cmd = nla_get_u32(info->attrs[KSMARTLINK_ATTR_SI_CMD]);
#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_set_si_cmd si_cmd=%d\n", si_cmd);
#endif
    }
    /* TODO: set si_cmd */
    ssv6xxx_send_si_cmd(si_cmd);

    return 0;
}

static int ksmartlink_get_si_status(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    int retval;
    void *hdr;
    char status[128] = "";

    if (info == NULL)
        return -EINVAL;

    /* TODO: get si_status */
    get_si_status((char *)status);

    /* allocate new netlink packet */
    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_get_si_status\n");
#endif

    hdr = genlmsg_put(msg, 0, info->snd_seq, &ksmartlink_gnl_family, 0, KSMARTLINK_CMD_GET_SI_STATUS);
    if (!hdr)
    {
        retval = -ENOBUFS;
        goto free_msg;
    }
    retval = nla_put_string(msg, KSMARTLINK_ATTR_SI_STATUS, status);
    if (retval)
    {
        printk("Fail to add attribute in message\n");
        goto free_msg;
    }

    genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

free_msg:
    nlmsg_free(msg);
    return retval;
}

static int ksmartlink_get_si_ssid(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    int retval;
    void *hdr;
    char ssid[128] = "";

    if (info == NULL)
        return -EINVAL;

    /* TODO: get si_status */
    get_si_ssid((char *)ssid);

    /* allocate new netlink packet */
    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_get_si_ssid\n");
#endif

    hdr = genlmsg_put(msg, 0, info->snd_seq, &ksmartlink_gnl_family, 0, KSMARTLINK_CMD_GET_SI_SSID);
    if (!hdr)
    {
        retval = -ENOBUFS;
        goto free_msg;
    }
    retval = nla_put_string(msg, KSMARTLINK_ATTR_SI_SSID, ssid);
    if (retval)
    {
        printk("Fail to add attribute in message\n");
        goto free_msg;
    }

    genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

free_msg:
    nlmsg_free(msg);
    return retval;
}

static int ksmartlink_get_si_pass(struct sk_buff *skb, struct genl_info *info)
{
    struct sk_buff *msg;
    int retval;
    void *hdr;
    char pass[128] = "";

    if (info == NULL)
        return -EINVAL;

    /* TODO: get si_status */
    get_si_pass((char *)pass);

    /* allocate new netlink packet */
    msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

#ifdef SSV_SMARTLINK_DEBUG
        printk("ksmartlink_get_si_pass\n");
#endif

    hdr = genlmsg_put(msg, 0, info->snd_seq, &ksmartlink_gnl_family, 0, KSMARTLINK_CMD_GET_SI_PASS);
    if (!hdr)
    {
        retval = -ENOBUFS;
        goto free_msg;
    }
    retval = nla_put_string(msg, KSMARTLINK_ATTR_SI_PASS, pass);
    if (retval)
    {
        printk("Fail to add attribute in message\n");
        goto free_msg;
    }

    genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

free_msg:
    nlmsg_free(msg);
    return retval;
}
#endif

int smartlink_nl_send_msg(struct sk_buff *skb_in)
{
    struct sk_buff *skb;
    int retval;
    void *msg_head;
    unsigned char *pOutBuf=skb_in->data;
    int inBufLen=skb_in->len;
    struct ssv_softc *ssv_smartlink_sc = ssv6xxx_driver_attach(SSV_DRVER_NAME);

    /* allocate new netlink packet */
    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (skb == NULL)
        return -ENOMEM;

    /* create the message headers */
    msg_head = genlmsg_put(skb, 0, 0, &ksmartlink_gnl_family, 0, KSMARTLINK_CMD_RX_FRAME);
    if (msg_head == NULL) 
    {
        retval = -ENOMEM;
        printk("Fail to create the netlink message header\n");
        goto free_msg;
    }
    /* fill with message */ 
    retval = nla_put(skb, KSMARTLINK_ATTR_RXFRAME, inBufLen, pOutBuf);
    if (retval != 0)
    {
        printk("Fail to add attribute in message\n");
        goto free_msg;
    }
    /* finalize the message */
    genlmsg_end(skb, msg_head);
    return genlmsg_unicast(&init_net, skb, ssv_smartlink_sc->ssv_usr_pid);

free_msg:
    nlmsg_free(skb);
    return retval;
}
EXPORT_SYMBOL(smartlink_nl_send_msg);

/* commands: ssv ksmartlink netlink ops */
struct genl_ops ksmartlink_gnl_ops[] = {
    {
        .cmd = KSMARTLINK_CMD_SMARTLINK,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_cmd_smartlink,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_SET_CHANNEL,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_set_channel,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_GET_CHANNEL,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_get_channel,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_SET_PROMISC,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_set_promisc,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_GET_PROMISC,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_get_promisc,
        .dumpit = NULL,
    },
#ifdef CONFIG_SSV_SMARTLINK
    {
        .cmd = KSMARTLINK_CMD_SMARTICOMM,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_start_smarticomm,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_SET_SI_CMD,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_set_si_cmd,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_GET_SI_STATUS,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_get_si_status,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_GET_SI_SSID,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_get_si_ssid,
        .dumpit = NULL,
    },
    {
        .cmd = KSMARTLINK_CMD_GET_SI_PASS,
        .flags = 0,
        .policy = ksmartlink_genl_policy,
        .doit = ksmartlink_get_si_pass,
        .dumpit = NULL,
    },
#endif
};

/* family definition */
static struct genl_family ksmartlink_gnl_family = {
    //.id = GENL_ID_GENERATE,
    .id = GLOBAL_NL_ID,
    .hdrsize = 0,
    .name = "KSMARTLINK",
    .version = 1,
    .maxattr = KSMARTLINK_ATTR_MAX, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    .ops        = ksmartlink_gnl_ops,
    .n_ops      = ARRAY_SIZE(ksmartlink_gnl_ops),
#endif
};

int ksmartlink_init(void)
{
    int rc;

    printk("INIT SSV KSMARTLINK GENERIC NETLINK MODULE\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    rc = genl_register_family(&ksmartlink_gnl_family);
    
    //printk("Fail to insert SSV KSMARTLINK NETLINK MODULE %d\n",ksmartlink_gnl_family.id);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
    rc = genl_register_family_with_ops(&ksmartlink_gnl_family, 
        ksmartlink_gnl_ops);
#else
    rc = genl_register_family_with_ops(&ksmartlink_gnl_family, 
        ksmartlink_gnl_ops, ARRAY_SIZE(ksmartlink_gnl_ops));
#endif
    if (rc != 0) 
    {
        printk("Fail to insert SSV KSMARTLINK NETLINK MODULE\n");
        return -1;
    }
#if 0
    if(ssv6xxx_driver_attach(SSV_DRVER_NAME) == NULL)
    {
        printk("Fail to attach WIFI friver\n");
        return -1;
    }
#endif
    return 0;
}

int ksmartlink_exit(void)
{
    int ret;

    printk("EXIT SSV KSMARTLINK GENERIC NETLINK MODULE\n");
    ret = genl_unregister_family(&ksmartlink_gnl_family);
    if(ret !=0) {
        printk("unregister family %i\n",ret);
    }

    printk("EXIT SSV KSMARTLINK GENERIC NETLINK MODULE ... end\n");
    return ret;
}

#if (defined(CONFIG_SSV_SUPPORT_ANDROID)||defined(CONFIG_SSV_BUILD_AS_ONE_KO))
EXPORT_SYMBOL(ksmartlink_init);
EXPORT_SYMBOL(ksmartlink_exit);
#endif


#endif

