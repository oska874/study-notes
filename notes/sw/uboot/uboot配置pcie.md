

### 0. 前导

ep，rc，
ppc inbound，outbound
type0 header，type1 header，configuration space

### 1. 访问 pcie 配置空间： 

???

rc 访问 pcie 配置空间：

```
#define INDIRECT_PCI_OP(rw, size, type, op, mask)                        \              
static int                                                               \              
indirect_##rw##_config_##size(struct pci_controller *hose,               \              
                  pci_dev_t dev, int offset, type val)       \                          
{                                                                        \              
    u32 b, d,f;                          \                                              
    b = PCI_BUS(dev); d = PCI_DEV(dev); f = PCI_FUNC(dev);       \                      
    b = b - hose->first_busno;                   \                                      
    dev = PCI_BDF(b, d, f);                      \                                      
    *(hose->cfg_addr) = dev | (offset & 0xfc) | ((offset & 0xf00) << 16) | 0x80000000; \
    sync();                                                          \                  
    cfg_##rw(val, hose->cfg_data + (offset & mask), type, op);       \                  
    return 0;                                                        \                  
}
```

```
#define INDIRECT_PCI_OP_ERRATA6(rw, size, type, op, mask)        \    
static int                               \                            
indirect_##rw##_config_##size(struct pci_controller *hose,       \    
                  pci_dev_t dev, int offset, type val)   \            
{                                    \                                
    unsigned int msr = mfmsr();                  \                    
    mtmsr(msr & ~(MSR_EE | MSR_CE));                 \                
    out_le32(hose->cfg_addr, dev | (offset & 0xfc) | 0x80000000);    \
    cfg_##rw(val, hose->cfg_data + (offset & mask), type, op);   \    
    out_le32(hose->cfg_addr, 0x00000000);                \            
    mtmsr(msr);                          \                            
    return 0;                            \                            
}
INDIRECT_PCI_OP(write, byte, u8, out_8, 3)     
INDIRECT_PCI_OP(write, word, u16, out_le16, 2) 
INDIRECT_PCI_OP(write, dword, u32, out_le32, 0)
```

PCI Express configuration address register(PEXx_PEX_CONFIG_ADDR)

address register contains address information for accesses to PCI Express internal and external configuration registers.

PCI Express configuration data register(PEXx_PEX_CONFIG_DATA)

configuration data register is a 32-bit port for internal and external configuration access.                         

rc 访问 pcie 域的配置空间

```
#define PCI_HOSE_OP(rw, size, type)                 \
int pci_hose_##rw##_config_##size(struct pci_controller *hose,      \
                  pci_dev_t dev,            \
                  int offset, type value)       \
{                                   \
    return hose->rw##_##size(hose, dev, offset, value);     \
}

PCI_HOSE_OP(read, byte, u8 *)
PCI_HOSE_OP(read, word, u16 *)
PCI_HOSE_OP(read, dword, u32 *)
PCI_HOSE_OP(write, byte, u8)
PCI_HOSE_OP(write, word, u16)
PCI_HOSE_OP(write, dword, u32)

#define PCI_OP(rw, size, type, error_code)              \
int pci_##rw##_config_##size(pci_dev_t dev, int offset, type value) \
{                                   \
    struct pci_controller *hose = pci_bus_to_hose(PCI_BUS(dev));    \
                                    \
    if (!hose)                          \
    {                               \
        error_code;                     \
        return -1;                      \
    }                               \
                                    \
    return pci_hose_##rw##_config_##size(hose, dev, offset, value); \
}

PCI_OP(read, byte, u8 *, *value = 0xff)
PCI_OP(read, word, u16 *, *value = 0xffff)
PCI_OP(read, dword, u32 *, *value = 0xffffffff)
PCI_OP(write, byte, u8, )
PCI_OP(write, word, u16, )
PCI_OP(write, dword, u32, )
```

`hose->rw##_##size` 实际调用的就是 `indirect_read_config_byte` 这些函数

```
void pci_setup_indirect(struct pci_controller* hose, u32 cfg_addr, u32 cfg_data)
{                                                                               
    pci_set_ops(hose,                                                           
            indirect_read_config_byte,                                          
            indirect_read_config_word,                                          
            indirect_read_config_dword,                                         
            indirect_write_config_byte,                                         
            indirect_write_config_word,                                         
            indirect_write_config_dword);                                       
                                                                                
    hose->cfg_addr = (unsigned int *) cfg_addr;                                 
    hose->cfg_data = (unsigned char *) cfg_data;                                
}
static inline void pci_set_ops(struct pci_controller *hose,  
                   int (*read_byte)(struct pci_controller*,  
                            pci_dev_t, int where, u8 *),     
                   int (*read_word)(struct pci_controller*,  
                            pci_dev_t, int where, u16 *),    
                   int (*read_dword)(struct pci_controller*, 
                             pci_dev_t, int where, u32 *),   
                   int (*write_byte)(struct pci_controller*, 
                             pci_dev_t, int where, u8),      
                   int (*write_word)(struct pci_controller*, 
                             pci_dev_t, int where, u16),     
                   int (*write_dword)(struct pci_controller*,
                              pci_dev_t, int where, u32)) {  
    hose->read_byte   = read_byte;                           
    hose->read_word   = read_word;                           
    hose->read_dword  = read_dword;                          
    hose->write_byte  = write_byte;                          
    hose->write_word  = write_word;                          
    hose->write_dword = write_dword;                         
}                                                                                                                                        
```

`pci_hose_read_config*` -> `hose->rw##_##size <==> indirect_read_config_*` ->

上述的函数到底会去读写那个 pcie 设备的配置空间，起决定作用的就是它们的*设备号、总线号* ， 在 uboot 中命令 pci 可以获取到所有 pcie 设备的信息，其实现为函数 `do_pci()` ：

```
static int do_pci(cmd_tbl_t *cmdtp, int flag, int argc, char * const argv[])
{                                                                           
...                                                  
        if ((bdf = get_pci_dev(argv[2])) == -1)                             
            return 1;                                                       
...                           
                                                         
    switch (argv[1][0]) {                                
    case 'h':       /* header */                         
        pci_header_show(bdf);                            
        return 0;                                        
    case 'd':       /* display */                        
        return pci_cfg_display(bdf, addr, size, value);  
#ifdef CONFIG_CMD_PCI_ENUM                               
    case 'e':                                            
        pci_init();                                      
        return 0;                                        
#endif                                                   
    case 'n':       /* next */                           
        if (argc < 4)                                    
            goto usage;                                  
        return pci_cfg_modify(bdf, addr, size, value, 0);
    case 'm':       /* modify */                         
        if (argc < 4)                                    
            goto usage;                                  
        return pci_cfg_modify(bdf, addr, size, value, 1);
    case 'w':       /* write */                          
        if (argc < 5)                                    
            goto usage;                                  
        return pci_cfg_write(bdf, addr, size, value);    
    }                                                    
                                                         
    return 1;                                            
 usage:                                                  
    return CMD_RET_USAGE;                                
}                                                        
```

`get_pci_dev()` 从用户输入获取总线 id 和设备 id：（funciton id 可以忽略）

```
=> pci h
pci - list and access PCI Configuration Space

Usage:
pci [bus] [long]
    - short or long list of PCI devices on bus 'bus'
pci header b.d.f
    - show header of PCI device 'bus.device.function'
pci display[.b, .w, .l] b.d.f [address] [# of objects]
    - display PCI configuration space (CFG)
pci next[.b, .w, .l] b.d.f address
    - modify, read and keep CFG address
pci modify[.b, .w, .l] b.d.f address
    -  modify, auto increment CFG address
pci write[.b, .w, .l] b.d.f address value
    - write to CFG address
```

比如要获取总线 id 为 0 、 设备 id 为 0 的 pcie 设备（此处就是 p1020 的 pcie 控制器） ：

```
=> pci h 0.0
  vendor ID =                   0x1957
  device ID =                   0x0101
  command register =            0x0006
  status register =             0x0010
  revision ID =                 0x11
  class code =                  0x0b (Processor)
  sub class code =              0x20
  programming interface =       0x00
  cache line =                  0x08
  latency time =                0x00
  header type =                 0x01
  BIST =                        0x00
  base address 0 =              0xfff00000
  base address 1 =              0x00000000
  primary bus number =          0x00
  secondary bus number =        0x01
  subordinate bus number =      0x01
  secondary latency timer =     0x00
  IO base =                     0x00
  IO limit =                    0x00
  secondary status =            0x0000
  memory base =                 0x8000
  memory limit =                0x8080
  prefetch memory base =        0x1001
  prefetch memory limit =       0x0001
  prefetch memory base upper =  0x00000000
  prefetch memory limit upper = 0x00000000
  IO base upper 16 bits =       0x0000
  IO limit upper 16 bits =      0x0000
  expansion ROM base address =  0x00000000
  interrupt line =              0x00
  interrupt pin =               0x00
  bridge control =              0x0000
```



#### 1.1. fpga dma ip

1. 需要配置 dma 核的地址映射表，然后 dma 的两片 ram 才能正确映射到 ddr
2. dma 的地址映射表的地址必须和 inbound 的起始地址对齐

### 2. 初始化pcie控制寄存器



### 3. 数据传输

ep 访问 rc ，指定了 pcie 域地址，然后 cpu 的 inbound address translator 会将 pcie 地址转换成本地域地址；

rc 访问 ep ，则通过 cpu 的 outbound address translator 将本地域地址转换成 pcie 域地址。


# Q
1. rc

base address 0 =              0xfff00000

2. ep

base address 0 =              0x8000000c
base address 1 =              0x00000000
base address 2 =              0x80800000





