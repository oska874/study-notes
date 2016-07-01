
驱动框架
========
<!-- MarkdownTOC -->

- 6. 驱动框架
  - 6.1. 声明
  - 6.2. uclasses
  - 6.3. 调用
  - 6.4. 设备的使用
  - 6.5. 小结

<!-- /MarkdownTOC -->

## 6. 驱动框架

### 6.1. 声明

- 方式 A

  每个设备在 uboot 中都对应一个驱动结构体变量， uboot 操纵外设都是通过该结构体变量实现的。以 ti 的 cpsw 网卡为例，在 `driver/net/cpsw.c` 中定义了多个函数实现了网卡的收发、配置、中断处理等操作，然后通过结构体将这些操作集成到操作结构体 `struct eth_ops` 中：
  
  ```
  static const struct eth_ops cpsw_eth_ops = { 
    .start      = cpsw_eth_start,
    .send       = cpsw_eth_send,
    .recv       = cpsw_eth_recv,
    .free_pkt   = cpsw_eth_free_pkt,
    .stop       = cpsw_eth_stop,
  };
  ```
  
  这个结构体包含了网卡的主要操作：启停、收发等操作，但是这个结构体还是太底层了，不应该直接传给上层应用，也不能传给上层，uboot 的外设驱动架构是把全部的驱动放到一个 **section 群**中，驱动结构体的成员是统一的，cpsw 驱动结构提其组成如下：
  
  ```
  U_BOOT_DRIVER(eth_cpsw) = {
    .name   = "eth_cpsw",
    .id = UCLASS_ETH,
    .of_match = cpsw_eth_ids,
    .ofdata_to_platdata = cpsw_eth_ofdata_to_platdata,
    .probe  = cpsw_eth_probe,
    .ops    = &cpsw_eth_ops,
    .priv_auto_alloc_size = sizeof(struct cpsw_priv),
    .platdata_auto_alloc_size = sizeof(struct eth_pdata),
    .flags = DM_FLAG_ALLOC_PRIV_DMA, 
  };
  ```
  
  cpsw 驱动的成员包括了驱动名（name）、id、类型（of_match)、探针（probe）、操作（ops）等等。而这些驱动都是保存在同一个 **section 群**中，这是通过宏 `U_BOOT_DRIVER` 实现的：
  
  ```
  /* Declare a new U-Boot driver */
  #define U_BOOT_DRIVER(__name)                       \
    ll_entry_declare(struct driver, __name, driver)

  #define ll_entry_declare(_type, _name, _list)               \
    _type _u_boot_list_2_##_list##_2_##_name __aligned(4)       \
            __attribute__((unused,              \
            section(".u_boot_list_2_"#_list"_2_"#_name)))  
  
  struct driver {
    char *name;
    enum uclass_id id;
    const struct udevice_id *of_match;
    int (*bind)(struct udevice *dev);
    int (*probe)(struct udevice *dev);
    int (*remove)(struct udevice *dev);
    int (*unbind)(struct udevice *dev);
    int (*ofdata_to_platdata)(struct udevice *dev);
    int (*child_post_bind)(struct udevice *dev);
    int (*child_pre_probe)(struct udevice *dev);
    int (*child_post_remove)(struct udevice *dev);
    int priv_auto_alloc_size;
    int platdata_auto_alloc_size;
    int per_child_auto_alloc_size;
    int per_child_platdata_auto_alloc_size;
    const void *ops;    /* driver-specific operations */
    uint32_t flags;
  };
  ```
  
  这和之前 shell command 的实现类似。此处网卡驱动 `eth_cpsw` 的结构体就是一个定义在段 `.u_boot_list_2_driver_2_eth_cpsw` 的 `struct driver` 结构体（`_u_boot_list_2_driver_2_eth_cpsw`)，定义好网卡驱动之后，其它应用就知道了结构体的名字和位置，从而可以使用该驱动。

- 方式 B
  
  方式 B 的驱动声明就相对简单多了 ， 实现网卡的各种操作接口还是必要的 ， 但是此时就不需要再声明定义额外的驱动结构体了，只需要定义一个网卡注册函数 `cpsw_register()` :

```
  int cpsw_register(struct cpsw_platform_data *data)
  {
    struct eth_device   *dev;
    ...
    priv->dev = dev;           
    priv->data = *data;        
                               
    strcpy(dev->name, "cpsw"); 
    dev->iobase = 0;           
    dev->init   = cpsw_init;   
    dev->halt   = cpsw_halt;   
    dev->send   = cpsw_send;   
    dev->recv   = cpsw_recv;   
    dev->priv   = priv;        
                               
    eth_register(dev);         
                               
    ret = _cpsw_register(priv);
    if (ret < 0) {             
        eth_unregister(dev);   
        free(dev);             
        free(priv);            
        return ret;            
    }                          
                               
    return 1;                  
  }
```

`cpsw_register()` 中会网卡的操作函数 `dev` 关联，并且通过接口 `eth_register()` (uboot 提供的网卡统一注册函数)与全局变量 `eth_register` 关联起来，供上层应用使用。

### 6.2. uclasses

### 6.3. 调用

  首先注册驱动，将具体设备的驱动和 uboot 的全局结构体（got？）关联起来。
  
  然后通过全局结构体调用具体的设备驱动。
  
  ```
  int eth_send(void *packet, int length)
  {
    ...
    return eth_current->send(eth_current, packet, length);
  } 
  ```
  
  uboot 通过 `eth_current->send` 调用了实际网络设备的发送函数。现在要关注的是 eth_current 实际指向的驱动是哪个，以及该变量是何时、何处赋值的。 (详见 6.1 节)


### 6.4. 设备的使用

#### 6.4.1. 网卡

如上所示 uboot 启动阶段会执行 `initr_net` 初始化网络：

```
static int initr_net(void)
{
...
    eth_initialize();
...
    return 0;
}
```

```
int eth_initialize(void)
{
    int num_devices = 0;

    eth_devices = NULL;
    eth_current = NULL;
    eth_common_init();
    /*
     * If board-specific initialization exists, call it.
     * If not, call a CPU-specific one
     */
    if (board_eth_init != __def_eth_init) {
        if (board_eth_init(gd->bd) < 0)
            printf("Board Net Initialization Failed\n");
    } else if (cpu_eth_init != __def_eth_init) {
        if (cpu_eth_init(gd->bd) < 0)
            printf("CPU Net Initialization Failed\n");
    } else {
        printf("Net Initialization Skipped\n");
    }
    if (!eth_devices) {
        puts("No ethernet found.\n");
        bootstage_error(BOOTSTAGE_ID_NET_ETH_START);
    } else {
        ...
        eth_current = dev;
        ...
    }
    ...
  }
```

在函数 `eth_initialize()` 中，会初始化网络地址、参数(`eth_common_init()`)，接着进入 `board_eth_init()` 注册网络设备，并给 `eth_current` 赋值。

```
int board_eth_init(bd_t *bis)
{
...
rv = cpsw_register(&cpsw_data);
...
}
```

```
int cpsw_register(struct cpsw_platform_data *data)
{       

  eth_register(dev);
  ...
}
```

```
int eth_register(struct eth_device *dev)
{
...
  eth_devices = dev;
  eth_current = dev;
...
}
```

以后对网卡的操作都会直接调用 `eth_current`。如 ping 操作最终会沿着函数调用链 ： `do_ping()`->`net_loop()`->`ping_start()`->`ping_send()`->`arp_request()`->`arp_raw_request()`->->`net_send_packet()`->`eth_send()`->`eth_current->send` 进行发包。

#### 6.4.2. 串口
uboot 启动阶段会执行 `initr_serial` 初始化串口终端，初始化函数调用链如下：

`initr_serial`->`serial_initialize`->`serial_init`->`serial_find_console_or_panic`

```
static void serial_find_console_or_panic(void)
{
  ...  
    if (!uclass_get_device_by_of_offset(UCLASS_SERIAL, node,
                    &dev)) {
      gd->cur_serial_dev = dev;
    return;
    }
  ...
    if (node > 0 &&
    !lists_bind_fdt(gd->dm_root, blob, node, &dev)) {
    if (!device_probe(dev)) {
        gd->cur_serial_dev = dev;
        return;
    }
  ...
    if (!uclass_get_device_by_seq(UCLASS_SERIAL, INDEX, &dev) ||
       !uclass_get_device(UCLASS_SERIAL, INDEX, &dev) ||
       (!uclass_first_device(UCLASS_SERIAL, &dev) && dev)) {
       gd->cur_serial_dev = dev;
       return;
    }
...    
}
```

串口驱动使用了**方式 B** 声明设备结构体，在使用宏 `U_BOOT_DRIVER` 定义设备结构体变量时，会给赋给设备 `.id=UCLASS_SERIAL` ， 然后初始化串口时会调用到 `uclass_add()` ，而这个函数会根据 id 去找设备结构体变量，然后将该设备添加到 `uc->dev_head` 和相关链表链表，并最后把设备指针传给 `gd->cur_serial_dev`。以后 uboot 使用串口进行收发包都是调用 `gd->cur_serial_dev` 进行的。

#### 6.4.3. 其他

其他外设大多类似，基本要么使用**方式 A** 通过 `init_sequence_r[]` 中的初始化函数进行配置的，同时驱动自己还需要提供一个接口进行设备注册；或者使用**方式 B** 定义设备结构体，然后由 uboot 根据设备 ID 找到对应的结构体。两种方法最终都是要把设备驱动和 gd 全局变量关联起来。



### 6.5. 小结

uboot 的驱动框架相对于 linux driver 来说很简单，但是相对一般裸板系统(以及 RTOS) 来说还是复杂些。

首先，uboot 的驱动实现和裸板系统的驱动类似，都是直接对设备寄存器、存储空间进行操作，所有的功能都要自己实现，不似 linux 已经提供了现成的同步、互斥接口，也不需要考虑内存申请、释放、地址转换等问题，可以说都很原始；

其次，虽然 uboot 的驱动实现很简单，但是使用方法和裸板驱动还是不同的，常见的裸板（包括 RTOS）驱动程序都是直接将底层操作接口暴露给上层应用，而 uboot 却对这些接口进行了封装，针对多平台的外设使用简化了使用复杂度：通过结构体将驱动操作接口和设备的全局变量（比如网卡相关全局变量为 `eth_current`）关联到一起，上层应用只要知道这个全局变量就可以进行设备操作，BSP 工程师要做的就是实现驱动并且在 uboot 初始化外设时将驱动接口和这个全局变量关联起来。

再次，uboot 的驱动还利用了 section 特性，将很多驱动声明在一堆连续的 section 区（如上所述，通过宏 `U_BOOT_DRIVER()` 将驱动结构体放到段 `.u_boot_list_2_driver_2_*`），后续如果要使用这些驱动，则只需要知道驱动名（如网卡 eth_cpsw）。

最后，uboot 的驱动框架是很简单的，既要兼顾多种外设、多种架构，但又要降低驱动的实现难度，提高驱动的执行效率，所以它的框架是针对功能性和复杂度的折中实现。而 uboot 不同设备驱动在具体实现时采用的框架流程并没有统一，不同类型有不同的执行套路，比较烦人。


注：

1. 方式 B 的具体用法还是有疑惑，没有完全搞清楚。
2. uclass ？
3. fdt ？
