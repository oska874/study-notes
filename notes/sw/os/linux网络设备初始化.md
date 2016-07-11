---
tags : linux , kernel , net
---


linux 网络设备初始化
===================


<!-- MarkdownTOC -->

- 1. net_dev_init
    - device driver init
    - 

<!-- /MarkdownTOC -->


## 1. net_dev_init

linux 下网络设备的实现分为两层：
- 抽象设备层 ： 提供一些设备无关的处理流程，也提供一些公用的函数给底层的 device driver 调用。它为网络协议提供统一的发送、接收接口。这部分根据输入输出请求，通过特定设备驱动程序接口，来与设备进行通信。
- 实际网卡驱动 ： 也就是具体的设备驱动程序，直接操作相应的设备。



```
static int __init net_dev_init(void)
{
    int i, rc = -ENOMEM;

    BUG_ON(!dev_boot_phase);

    if (dev_proc_init())
        goto out;

    if (netdev_kobject_init())
        goto out;

    INIT_LIST_HEAD(&ptype_all);
    for (i = 0; i < PTYPE_HASH_SIZE; i++)
        INIT_LIST_HEAD(&ptype_base[i]);

    INIT_LIST_HEAD(&offload_base);

    if (register_pernet_subsys(&netdev_net_ops))
        goto out;

    /*
     *  Initialise the packet receive queues.
     */

    for_each_possible_cpu(i) {
        struct softnet_data *sd = &per_cpu(softnet_data, i);

        memset(sd, 0, sizeof(*sd));
        skb_queue_head_init_raw(&sd->input_pkt_queue);
        skb_queue_head_init_raw(&sd->process_queue);
        skb_queue_head_init_raw(&sd->tofree_queue);
        sd->completion_queue = NULL;
        INIT_LIST_HEAD(&sd->poll_list);
        sd->output_queue = NULL;
        sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
        sd->csd.func = rps_trigger_softirq;
        sd->csd.info = sd;
        sd->csd.flags = 0;
        sd->cpu = i;
#endif

        sd->backlog.poll = process_backlog;
        sd->backlog.weight = weight_p;
        sd->backlog.gro_list = NULL;
        sd->backlog.gro_count = 0;

#ifdef CONFIG_NET_FLOW_LIMIT
        sd->flow_limit = NULL;
#endif
    }

    dev_boot_phase = 0;

    /* The loopback device is special if any other network devices
     * is present in a network namespace the loopback device must
     * be present. Since we now dynamically allocate and free the
     * loopback device ensure this invariant is maintained by
     * keeping the loopback device as the first device on the
     * list of network devices.  Ensuring the loopback devices
     * is the first device that appears and the last network device
     * that disappears.
     */
    if (register_pernet_device(&loopback_net_ops))
        goto out;

    if (register_pernet_device(&default_device_ops))
        goto out;

    open_softirq(NET_TX_SOFTIRQ, net_tx_action);
    open_softirq(NET_RX_SOFTIRQ, net_rx_action);

    hotcpu_notifier(dev_cpu_callback, 0);
    dst_init();
    rc = 0;
out:
    return rc;
}

subsys_initcall(net_dev_init);
```

`/proc` 、 `/sys` 、 每个 CPU 的 receive 队列 、 loopback 、 TX/RX softirq 、


### device driver init

网卡驱动模块  `module_init`

### 

net namespace
register_pernet_subsys