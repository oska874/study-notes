---
tags : [ Linux ]
---

<!-- MarkdownTOC -->

- 1. 软件中断
- 2. 系统调用流程
    - 2.1. 进入软件中断
    - 2.2. 选择系统调用
    - 2.3. 执行系统调用

<!-- /MarkdownTOC -->


## 1. 软件中断

## 2. 系统调用流程

### 2.1. 进入软件中断

### 2.2. 选择系统调用

### 2.3. 执行系统调用



---

arm

arch/arm/kernel/entry-common.S

```
ENTRY(vector_swi)


```

ppc

`arch/powerpc/kernel/entry_32.S`

```
 _GLOBAL(DoSyscall)


```

x86

`arch/x86/kernel/entry_32.S`

```
ENTRY(system_call)


```
