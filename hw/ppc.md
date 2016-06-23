
(以下内容试用于 freescale 的 mpc83xx 和 p1020 系列）

1. ddr ecc
  - mpc8308 和 p1020 都支持 ddr 的 ecc 校验，硬件上需要附加一块 ddr 作为 ecc 内存来存储 ecc 校验值，换言之要使能 ecc 需要两块 ddr ， 一块供程序使用，一块供 ecc 使用。
  - 使能 ecc 需要在初始化 ddr 之前完成，对于 uboot 来说，就是要在初始化 ddr 控制器、将 flash 的数据拷贝到内存之前就把 ecc 相关的寄存器配置好，举个例子，对于 p1020 来说，需要在函数 `initdram()` 里调用 `ddr_enable_ecc()` 使能 ecc ,而 `initdram()` 就是再拷贝 flash 数据之前执行的， `ddr_enable_ecc()` 也是在配置 ddr 的过程中调用的。
  - 使能完 ecc 之后不能立即读内存，因为此时的内存的 ecc 校验值都是乱的，直接读取内存肯定会发生 ecc 错误，所以执行之前需要把所有内存初始化一遍，即全部写一遍。
  - ppc 的 ddr ecc 支持纠正一位错，可以检测两位错和多位的 nibble 错（注：nibble 错误是啥？）。ecc 的校验算法和 FCM 的 ecc 校验算法相同。

2. 内存长度配置
  ppc 配置内存长度有多处寄存器需要设置：
  - LAW ： LAW_LAWBAR
  - localbus ： eLBC_ORg
  - ddr 控制器 ： DDR_CSn_BNDS
  - mmu ： tlb 
  
3. 外部中断处理
 需要注意两点：中断号，中断触发方式。后者要配置中断触发高低电平和
