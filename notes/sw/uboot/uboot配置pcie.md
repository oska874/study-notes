

### 0. 前导

ep，rc，
ppc inbound，outbound
type0 header，type1 header，configuration space

### 1. 访问 pcie 配置空间： 

rc 访问 ep 的配置空间：

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

rc 访问自己的配置空间

直接操作寄存器


#### 1.1. fpga dma ip

1. 需要配置 dma 核的地址映射表，然后 dma 的两片 ram 才能正确映射到 ddr
2. dma 的地址映射表的地址必须和 inbound 的起始地址对齐

### 2. 初始化pcie控制寄存器