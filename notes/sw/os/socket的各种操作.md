---
tags : [ net , kernel , Linux ]
---


<!-- MarkdownTOC -->

- 1. 创建套接字（`socket`）
    - 1.1. 总结
- 2. 连接（`connect`）
- 3. 绑定（`bind`）
- 4. 发送
- 5. 接收
- 6. 关闭连接（`close`）

<!-- /MarkdownTOC -->

## 1. 创建套接字（`socket`）

`sys_create` 

`net/socket.c`

```
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
    int retval;
    struct socket *sock;
    int flags;

    /* Check the SOCK_* constants for consistency.  */
    BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
    BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
    BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
    BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

    flags = type & ~SOCK_TYPE_MASK;
    if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
        return -EINVAL;
    type &= SOCK_TYPE_MASK;

    if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
        flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

    retval = sock_create(family, type, protocol, &sock);
    if (retval < 0)
        goto out;

    retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
    if (retval < 0)
        goto out_release;

out:
    /* It may be already another descriptor 8) Not kernel problem. */
    return retval;

out_release:
    sock_release(sock);
    return retval;
}
```

主要是两个操作: 创建 socket（ `sock_create`） 和获取 socket 文件 id （`sock_map_fd`）。

```
int sock_create(int family, int type, int protocol, struct socket **res)           
{
    return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}

int __sock_create(struct net *net, int family, int type, int protocol,      
             struct socket **res, int kern)                                 
{                                                                           
    int err;                                                                
    struct socket *sock;                                                    
    const struct net_proto_family *pf;                                      
                                                                            
    /*                                                                      
     *      Check protocol is in range                                      
     */                                                                     
    if (family < 0 || family >= NPROTO)                                     
        return -EAFNOSUPPORT;                                               
    if (type < 0 || type >= SOCK_MAX)                                       
        return -EINVAL;                                                     
                                                                            
    /* Compatibility.                                                       
                                                                            
       This uglymoron is moved from INET layer to here to avoid             
       deadlock in module load.                                             
     */                                                                     
    if (family == PF_INET && type == SOCK_PACKET) {                         
        static int warned;                                                  
        if (!warned) {                                                      
            warned = 1;                                                     
            printk(KERN_INFO "%s uses obsolete (PF_INET,SOCK_PACKET)\n",    
                   current->comm);                                          
        }                                                                   
        family = PF_PACKET;                                                 
    }                                                                       
                                                                            
    err = security_socket_create(family, type, protocol, kern);             
    if (err)                                                                
        return err;                                                         
                                                                            
    /*                                                                      
     *  Allocate the socket and allow the family to set things up. if       
     *  the protocol is 0, the family is instructed to select an appropriate
     *  default.                                                            
     */                                                                     
    sock = sock_alloc();                                                    
    if (!sock) {                                                            
        net_warn_ratelimited("socket: no more sockets\n");                  
        return -ENFILE; /* Not exactly a match, but its the                 
                   closest posix thing */                                   
    }                                                                       
                                                                            
    sock->type = type;                                                      
    #ifdef CONFIG_MODULES                                                      
    /* Attempt to load a protocol module if the find failed.               
     *                                                                     
     * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user   
     * requested real, full-featured networking support upon configuration.
     * Otherwise module support will break!                                
     */                                                                    
    if (rcu_access_pointer(net_families[family]) == NULL)                  
        request_module("net-pf-%d", family);                               
    #endif                                                                     
                                                                           
    rcu_read_lock();                                                       
    pf = rcu_dereference(net_families[family]);                            
    err = -EAFNOSUPPORT;                                                   
    if (!pf)                                                               
        goto out_release;                                                  
                                                                           
    /*                                                                     
     * We will call the ->create function, that possibly is in a loadable  
     * module, so we have to bump that loadable module refcnt first.       
     */                                                                    
    if (!try_module_get(pf->owner))                                        
        goto out_release;                                                  
                                                                           
    /* Now protected by module ref count */                                
    rcu_read_unlock();                                                     
                                                                           
    err = pf->create(net, sock, protocol, kern);                           
    if (err < 0)                                                           
        goto out_module_put;                                               
                                                                           
    /*                                                                     
     * Now to bump the refcnt of the [loadable] module that owns this      
     * socket at sock_release time we decrement its refcnt.                
     */                                                                    
    if (!try_module_get(sock->ops->owner))                                 
        goto out_module_busy;                                              
                                                                           
    /*                                                                     
     * Now that we're done with the ->create function, the [loadable]      
     * module can have its refcnt decremented                              
     */                                                                    
    module_put(pf->owner);                                                 
    err = security_socket_post_create(sock, family, type, protocol, kern); 
    if (err)                                                               
        goto out_sock_release;                                             
    *res = sock;                                                           
                                                                           
    return 0;                                                              
                                                                           
out_module_busy:                                                           
    err = -EAFNOSUPPORT;                                                   
out_module_put:                                                            
    sock->ops = NULL;                                                      
    module_put(pf->owner);                                                 
out_sock_release:                                                          
    sock_release(sock);                                                    
    return err; 
    out_release:              
    rcu_read_unlock();    
    goto out_sock_release;
}
```

`sock_alloc`

```
static struct socket *sock_alloc(void)
{
    struct inode *inode;
    struct socket *sock;

    inode = new_inode_pseudo(sock_mnt->mnt_sb);
    if (!inode)
        return NULL;

    sock = SOCKET_I(inode);

    kmemcheck_annotate_bitfield(sock, type);
    inode->i_ino = get_next_ino();
    inode->i_mode = S_IFSOCK | S_IRWXUGO;
    inode->i_uid = current_fsuid();
    inode->i_gid = current_fsgid();
    inode->i_op = &sockfs_inode_ops;

    this_cpu_add(sockets_in_use, 1);
    return sock;
}
```

`new_inode_pseudo` 获取一个 inode - 其所属的 superblock 不能被 umount，且不支持配额、fsnotify、写回等功能。获取 inode 结构体实际是通过 `sock_mnt->mnt_sb->alloc_inode` 即 `sock_alloc_inode` 完成的，其实质就是调用 `kmem_cache_alloc` 得到一块 `socket_alloc` 空间。

然后对 inode 进行赋值，要赋给它用户 id 、 组id 、 关联的 `sockfs_inode_ops` 操作.

最后增加当前 cpu 核的 socket 计数 ， 这个操作是和 CPU 绑定的，含义有二：

1. `this_cpu_add` 操作只是在执行操作的 CPU 核上执行；
    ```
    `this_cpu_add(sockets_in_use, 1);`
    ```
2. `sockets_in_use` 变量每个 CPU 核都有自己的定义：
    ```
    static DEFINE_PER_CPU(int, sockets_in_use);
    ```

创建好 inode 结构体之后开始创建 socket 结构体。 pf 是 PF_INET 协议族的结构体（`net_families[PF_INET]`）， `pf->create` 创建 socket 是通过 `inet_create` 实现的，这是在协议栈初始化阶段注册的（`(void)sock_register(&inet_family_ops);`）.

到此 socket 和对应 inode 就创建好了并关联起来，下一步就是创建对应的套接字文件描述符并建立关联。

创建套接字文件并建立映射：

```
static int sock_map_fd(struct socket *sock, int flags)
{                                                     
    struct file *newfile;                             
    int fd = get_unused_fd_flags(flags);              
    if (unlikely(fd < 0))                             
        return fd;                                    
                                                      
    newfile = sock_alloc_file(sock, flags, NULL);     
    if (likely(!IS_ERR(newfile))) {                   
        fd_install(fd, newfile);                      
        return fd;                                    
    }                                                 
                                                      
    put_unused_fd(fd);                                
    return PTR_ERR(newfile);                          
}                                                   
```

可以分为三步：

1. `get_unused_fd_flags` 分配 fd 并标记为 busy
2. `sock_alloc_file` 创建文件结构体
3. `fd_install` 将 fd 和文件结构体关联起来

### 1.1. 总结

应用层调用 socket 创建套接字在内核层要进行的操作可以分为 步：

1. 申请分配 socket 结构体；
2. 创建 socket 文件；
3. 生成 inode；
4. 关联 inode 和 socket 文件；
4. 得到文件描述符；
5. 关联文件描述符和 socket 文件。

## 2. 连接（`connect`）


## 3. 绑定（`bind`）


## 4. 发送

send ， sendto

tcp ， udp

## 5. 接收

recv ， recvfrom

tcp ， udp

## 6. 关闭连接（`close`）
