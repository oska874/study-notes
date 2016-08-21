---
tags : [ net , Kernel , Linux ]
category : [ 读核 ]
---


## 0. socket 相关的系统调用

socket 的操作，如 `socket` 、 `connect` 、 `accept` 都是系统调用， C 库通过软件中断（不是 CPU 的软中断）进入内核态执行系统调用。

（本文使用的内核版本为 4.6.0 , 84787c572d4）

## 1. 创建套接字（`socket`）

套接字虽然也是文件，但是不能用 open 来创建，必须使用 socket 系统调用创建，`socket` 在内核对应的系统调用是 `sys_create` ，在 `net/socket.c` 定义，使用 `SYSCALL_DEFINE3` 宏定义的。

```
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
...
    retval = sock_create(family, type, protocol, &sock);
    if (retval < 0)
        goto out;

    retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
    if (retval < 0)
        goto out_release;
...
}
```

主要是两个操作: 创建 socket （ `sock_create`） 文件和获取 socket 文件描述符 （`sock_map_fd`）。

### 1.1. 创建 socket 文件：

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

首先获取 socket 结构体和 i 节点:

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

```
static int inet_create(struct net *net, struct socket *sock, int protocol,
               int kern)
{
    struct sock *sk;
    struct inet_protosw *answer;
    struct inet_sock *inet;
    struct proto *answer_prot;
    unsigned char answer_flags;
    int try_loading_module = 0;
    int err;

    if (protocol < 0 || protocol >= IPPROTO_MAX)
        return -EINVAL;

    sock->state = SS_UNCONNECTED;

    /* Look for the requested type/protocol pair. */
lookup_protocol:
    err = -ESOCKTNOSUPPORT;
    rcu_read_lock();

    /*
        首先检查是否是 ip 协议
    */
    list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

        err = 0;
        /* Check the non-wild match. */
        if (protocol == answer->protocol) {
            if (protocol != IPPROTO_IP)
                break;
        } else {
            /* Check for the two wild cases. */
            if (IPPROTO_IP == protocol) {
                protocol = answer->protocol;
                break;
            }
            if (IPPROTO_IP == answer->protocol)
                break;
        }
        err = -EPROTONOSUPPORT;
    }

    if (unlikely(err)) {
        if (try_loading_module < 2) {
            rcu_read_unlock();
            /*
             * Be more specific, e.g. net-pf-2-proto-132-type-1
             * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
             */
            if (++try_loading_module == 1)
                request_module("net-pf-%d-proto-%d-type-%d",
                           PF_INET, protocol, sock->type);
            /*
             * Fall back to generic, e.g. net-pf-2-proto-132
             * (net-pf-PF_INET-proto-IPPROTO_SCTP)
             */
            else
                request_module("net-pf-%d-proto-%d",
                           PF_INET, protocol);
            goto lookup_protocol;
        } else
            goto out_rcu_unlock;
    }

    err = -EPERM;
    if (sock->type == SOCK_RAW && !kern &&
        !ns_capable(net->user_ns, CAP_NET_RAW))
        goto out_rcu_unlock;

    sock->ops = answer->ops;
    answer_prot = answer->prot;
    answer_flags = answer->flags;
    rcu_read_unlock();

    WARN_ON(!answer_prot->slab);

    err = -ENOBUFS;
    sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
    if (!sk)
        goto out;

    err = 0;
    if (INET_PROTOSW_REUSE & answer_flags)
        sk->sk_reuse = SK_CAN_REUSE;

    inet = inet_sk(sk);
    inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

    inet->nodefrag = 0;

    if (SOCK_RAW == sock->type) {
        inet->inet_num = protocol;
        if (IPPROTO_RAW == protocol)
            inet->hdrincl = 1;
    }

    if (net->ipv4.sysctl_ip_no_pmtu_disc)
        inet->pmtudisc = IP_PMTUDISC_DONT;
    else
        inet->pmtudisc = IP_PMTUDISC_WANT;

    inet->inet_id = 0;

    sock_init_data(sock, sk);

    sk->sk_destruct    = inet_sock_destruct;
    sk->sk_protocol    = protocol;
    sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

    inet->uc_ttl    = -1;
    inet->mc_loop   = 1;
    inet->mc_ttl    = 1;
    inet->mc_all    = 1;
    inet->mc_index  = 0;
    inet->mc_list   = NULL;
    inet->rcv_tos   = 0;

    sk_refcnt_debug_inc(sk);

    if (inet->inet_num) {
        /* It assumes that any protocol which allows
         * the user to assign a number at socket
         * creation time automatically
         * shares.
         */
        inet->inet_sport = htons(inet->inet_num);
        /* Add to protocol hash chains. */
        err = sk->sk_prot->hash(sk);
        if (err) {
            sk_common_release(sk);
            goto out;
        }
    }

    if (sk->sk_prot->init) {
        err = sk->sk_prot->init(sk);
        if (err)
            sk_common_release(sk);
    }
out:
    return err;
out_rcu_unlock:
    rcu_read_unlock();
    goto out;
}
```

到此 socket 和对应 inode 就创建好了并关联起来，下一步就是创建对应的套接字文件描述符并建立关联。

### 1.2. 创建套接字文件并建立映射：

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


### 1.3. 总结

应用层调用 socket 创建套接字在内核层要进行的操作可以分为 步：

1. 申请分配 socket 结构体；
2. 创建 socket 文件；
3. 生成 inode；
4. 关联 inode 和 socket 文件；
4. 得到文件描述符；
5. 关联文件描述符和 socket 文件。

## 2. 绑定（`bind`）

`bind` 操作是服务器在创建了套接字之后进行的操作，用来讲套接字和本地 IP 地址关联起来。它的实现也位于 `net/socket.c` 中，作为系统调用也是通过宏 `SYSCALL_DEFINE3` 定义的，函数名为 `sys_bind` ，有三个参数：套接字文件描述符、套接字地址结构体、结构体长度。

```
SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{                                                                              
    struct socket *sock;                                                       
    struct sockaddr_storage address;                                           
    int err, fput_needed;                                                      
                                                                               
    sock = sockfd_lookup_light(fd, &err, &fput_needed);                        
    if (sock) {                                                                
        err = move_addr_to_kernel(umyaddr, addrlen, &address);                 
        if (err >= 0) {                                                        
            err = security_socket_bind(sock,                                   
                           (struct sockaddr *)&address,                        
                           addrlen);                                           
            if (!err)                                                          
                err = sock->ops->bind(sock,                                    
                              (struct sockaddr *)                              
                              &address, addrlen);                              
        }                                                                      
        fput_light(sock->file, fput_needed);                                   
    }                                                                          
    return err;                                                                
}                                                                              
```

## 3. 连接（`connect`）

应用层连接操作对应内核的函数是 `sys_connect` ，定义方法同 socket ：

```
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,      
        int, addrlen)                                                       
{                                                                           
    struct socket *sock;                                                    
    struct sockaddr_storage address;                                        
    int err, fput_needed;                                                   
                                                                            
    sock = sockfd_lookup_light(fd, &err, &fput_needed);                     
    if (!sock)                                                              
        goto out;                                                           
    err = move_addr_to_kernel(uservaddr, addrlen, &address);                
    if (err < 0)                                                            
        goto out_put;                                                       
                                                                            
    err =                                                                   
        security_socket_connect(sock, (struct sockaddr *)&address, addrlen);
    if (err)                                                                
        goto out_put;                                                       
                                                                            
    err = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,    
                 sock->file->f_flags);                                      
out_put:                                                                    
    fput_light(sock->file, fput_needed);                                    
out:                                                                        
    return err;                                                             
}                                                                           
```

## 4. 监听（listen）

## 5. 接受（accept）

## 6. 发送

[][send1]

send 

```
/*                                                              
 *  Send a datagram down a socket.                              
 */                                                             
                                                                
SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
        unsigned int, flags)                                    
{                                                               
    return sys_sendto(fd, buff, len, flags, NULL, 0);           
}                                                               
```

sendto

```
/*                                                                      
 *  Send a datagram to a given address. We move the address into kernel 
 *  space and check the user space data area is readable before invoking
 *  the protocol.                                                       
 */                                                                     
                                                                        
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,      
        unsigned int, flags, struct sockaddr __user *, addr,            
        int, addr_len)                                                  
{                                                                       
    struct socket *sock;                                                
    struct sockaddr_storage address;                                    
    int err;                                                            
    struct msghdr msg;                                                  
    struct iovec iov;                                                   
    int fput_needed;                                                    
                                                                        
    err = import_single_range(WRITE, buff, len, &iov, &msg.msg_iter);   
    if (unlikely(err))                                                  
        return err;                                                     
    sock = sockfd_lookup_light(fd, &err, &fput_needed);                 
    if (!sock)                                                          
        goto out;                                                       
                                                                        
    msg.msg_name = NULL;                                                
    msg.msg_control = NULL;                                             
    msg.msg_controllen = 0;                                             
    msg.msg_namelen = 0;                                                
    if (addr) {                                                         
        err = move_addr_to_kernel(addr, addr_len, &address);            
        if (err < 0)                                                    
            goto out_put;                                               
        msg.msg_name = (struct sockaddr *)&address;                     
        msg.msg_namelen = addr_len;                                     
    }                                                                   
    if (sock->file->f_flags & O_NONBLOCK)                               
        flags |= MSG_DONTWAIT;                                          
    msg.msg_flags = flags;                                              
    err = sock_sendmsg(sock, &msg);                                     
                                                                        
out_put:                                                                
    fput_light(sock->file, fput_needed);                                
out:                                                                    
    return err;                                                         
}                                                                       
```


sendmsg

```
SYSCALL_DEFINE3(sendmsg, int, fd, struct user_msghdr __user *, msg, unsigned int, flags)
{                                                                                       
    if (flags & MSG_CMSG_COMPAT)                                                        
        return -EINVAL;                                                                 
    return __sys_sendmsg(fd, msg, flags);                                               
}    
```



## 7. 接收

recv ， recvfrom

tcp ， udp

## 8. 关闭连接（`close`）

## 9. ioctl

`ioctl` 是标准库函数，大部分操作系统都会支持这个操作函数，它是内核模块和应用程序交互配置的一种手段，而且是同步操作。ioctl 函数在内核中对应的函数是 `sys_ioctl` ，这个接口的操作属于 `VFS` 的，不区分用户要对哪种文件系统进行 ioctl ，只根据用户之前打开的文件类型来推断正确的调用路径。

`ioctl` 对应内核的系统调用是 `vfs_ioctl` ， 它会通过 `filp->f_op->unlocked_ioctl(...)` 文件对应的 `ioctl` 实现。对于套接字来说调用的就是 `sock_ioctl` 。 

`socket` 对应 vfs 的文件操作（ `file_operations` ） 为 `socket_file_ops` ，创建套接字时会调用 `sock_alloc_file()` ，这个函数会将 `socket_file_ops` 和 套接字文件关联起来（ `file = alloc_file(&path, FMODE_READ | FMODE_WRITE,&socket_file_ops);`）， `socket_file_ops` 定义在 `net/socket.c` ：

```
static const struct file_operations socket_file_ops = {
    .owner =    THIS_MODULE,                           
    .llseek =   no_llseek,                             
    .read_iter =    sock_read_iter,                    
    .write_iter =   sock_write_iter,                   
    .poll =     sock_poll,                             
    .unlocked_ioctl = sock_ioctl,                      
#ifdef CONFIG_COMPAT                                   
    .compat_ioctl = compat_sock_ioctl,                 
#endif                                                 
    .mmap =     sock_mmap,                             
    .release =  sock_close,                            
    .fasync =   sock_fasync,                           
    .sendpage = sock_sendpage,                         
    .splice_write = generic_splice_sendpage,           
    .splice_read =  sock_splice_read,                  
};                                                     
```

其中就指明了 `socket` 对应的 `ioctl` 为 `sock_ioctl` ， 定义在 `net/socket.c` ：

```
/*                                                                        
 *  With an ioctl, arg may well be a user mode pointer, but we don't know 
 *  what to do with it - that's up to the protocol still.                 
 */                                                                       
                                                                          
static long sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{                                                                         
    struct socket *sock;                                                  
    struct sock *sk;                                                      
    void __user *argp = (void __user *)arg;                               
    int pid, err;                                                         
    struct net *net;                                                      
                                                                          
    sock = file->private_data;                                            
    sk = sock->sk;                                                        
    net = sock_net(sk);                                                   
    if (cmd >= SIOCDEVPRIVATE && cmd <= (SIOCDEVPRIVATE + 15)) {          
        err = dev_ioctl(net, cmd, argp);                                  
    } else                                                                
#ifdef CONFIG_WEXT_CORE                                                   
    if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {                        
        err = dev_ioctl(net, cmd, argp);                                  
    } else                                                                
#endif                                                                    
        switch (cmd) {                                                    
        case FIOSETOWN:                                                   
        case SIOCSPGRP:                                                   
            err = -EFAULT;                                                
            if (get_user(pid, (int __user *)argp))                        
                break;                                                    
            f_setown(sock->file, pid, 1);                                 
            err = 0;                                                      
            break;                                  
        case FIOGETOWN:                             
        case SIOCGPGRP:                             
            err = put_user(f_getown(sock->file),    
                       (int __user *)argp);         
            break;                                  
        case SIOCGIFBR:                             
        case SIOCSIFBR:                             
        case SIOCBRADDBR:                           
        case SIOCBRDELBR:                           
            err = -ENOPKG;                          
            if (!br_ioctl_hook)                     
                request_module("bridge");           
                                                    
            mutex_lock(&br_ioctl_mutex);            
            if (br_ioctl_hook)                      
                err = br_ioctl_hook(net, cmd, argp);
            mutex_unlock(&br_ioctl_mutex);          
            break;                                  
        case SIOCGIFVLAN:                           
        case SIOCSIFVLAN:                           
            err = -ENOPKG;                          
            if (!vlan_ioctl_hook)                   
                request_module("8021q");            
                                                    
            mutex_lock(&vlan_ioctl_mutex);          
            if (vlan_ioctl_hook)                    
                err = vlan_ioctl_hook(net, argp);   
            mutex_unlock(&vlan_ioctl_mutex);        
            break;                                  
        case SIOCADDDLCI:                            
        case SIOCDELDLCI:                            
            err = -ENOPKG;                           
            if (!dlci_ioctl_hook)                    
                request_module("dlci");              
                                                     
            mutex_lock(&dlci_ioctl_mutex);           
            if (dlci_ioctl_hook)                     
                err = dlci_ioctl_hook(cmd, argp);    
            mutex_unlock(&dlci_ioctl_mutex);         
            break;                                   
        default:                                     
            err = sock_do_ioctl(net, sock, cmd, arg);
            break;                                   
        }                                            
    return err;                                      
}                                                    
```

从代码可以看到 `sock_ioctl` 支持多个选项，对于套接字网络设备来说最主要的处理函数是 `sock_do_ioctl()` 和 `dev_ioctl()` ：

`net/socket.c`

```
static long sock_do_ioctl(struct net *net, struct socket *sock,
                 unsigned int cmd, unsigned long arg)          
{                                                              
    int err;                                                   
    void __user *argp = (void __user *)arg;                    
                                                               
    err = sock->ops->ioctl(sock, cmd, arg);                    
                                                               
    /*                                                         
     * If this ioctl is unknown try to hand it down            
     * to the NIC driver.                                      
     */                                                        
    if (err == -ENOIOCTLCMD)                                   
        err = dev_ioctl(net, cmd, argp);                       
                                                               
    return err;                                                
}                                                              
```

其中 `sock->ops` 的值是在 `inet_create` 赋值的： `sock->ops = answer->ops;` ，而 `answer` 对应的就是 `inetsw[]` ，`inetsw` 数组是在网络协议栈初始化时赋值的对应的内容就是数组 `inetsw_array` （参见**linux网络协议栈初始化** 3.2. 添加网络协议 `inet_add_protocol()`）。

 `sock->ops->ioctl` 调用的函数会根据套接字类型不同而而不同，以 tcp 为例，`sock->ops` 对应 `inet_stream_ops` ：

`net/ipv4/af_inet.c` 

```
 const struct proto_ops inet_stream_ops = {             
    .family        = PF_INET,                          
    .owner         = THIS_MODULE,                      
    .release       = inet_release,                     
    .bind          = inet_bind,                        
    .connect       = inet_stream_connect,              
    .socketpair    = sock_no_socketpair,               
    .accept        = inet_accept,                      
    .getname       = inet_getname,                     
    .poll          = tcp_poll,                         
    .ioctl         = inet_ioctl,                       
    .listen        = inet_listen,                      
    .shutdown      = inet_shutdown,                    
    .setsockopt    = sock_common_setsockopt,           
    .getsockopt    = sock_common_getsockopt,           
    .sendmsg       = inet_sendmsg,                     
    .recvmsg       = inet_recvmsg,                     
    .mmap          = sock_no_mmap,                     
    .sendpage      = inet_sendpage,                    
    .splice_read       = tcp_splice_read,              
#ifdef CONFIG_COMPAT                                   
    .compat_setsockopt = compat_sock_common_setsockopt,
    .compat_getsockopt = compat_sock_common_getsockopt,
    .compat_ioctl      = inet_compat_ioctl,            
#endif                                                 
};                                                     
EXPORT_SYMBOL(inet_stream_ops);                        
```

其中 `ioctl` 对应的就是 `inet_ioctl` ：

`net/ipv4/af_inet.c`

```
/*                                                                      
 *  ioctl() calls you can issue on an INET socket. Most of these are    
 *  device configuration and stuff and very rarely used. Some ioctls    
 *  pass on to the socket itself.                                       
 *                                                                      
 *  NOTE: I like the idea of a module for the config stuff. ie ifconfig 
 *  loads the devconfigure module does its configuring and unloads it.  
 *  There's a good 20K of config code hanging around the kernel.        
 */                                                                     
                                                                        
int inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{                                                                       
    struct sock *sk = sock->sk;                                         
    int err = 0;                                                        
    struct net *net = sock_net(sk);                                     
                                                                        
    switch (cmd) {                                                      
    case SIOCGSTAMP:                                                    
        err = sock_get_timestamp(sk, (struct timeval __user *)arg);     
        break;                                                          
    case SIOCGSTAMPNS:                                                  
        err = sock_get_timestampns(sk, (struct timespec __user *)arg);  
        break;                                                          
    case SIOCADDRT:                                                     
    case SIOCDELRT:                                                     
    case SIOCRTMSG:                                                     
        err = ip_rt_ioctl(net, cmd, (void __user *)arg);                
        break;                                                          
    case SIOCDARP:                                                      
    case SIOCGARP:                                                      
    case SIOCSARP:                                                      
        err = arp_ioctl(net, cmd, (void __user *)arg);                  
        break;                                                          
    case SIOCGIFADDR:                                                   
    case SIOCSIFADDR:                                                   
    case SIOCGIFBRDADDR:                                                
    case SIOCSIFBRDADDR:                                                
    case SIOCGIFNETMASK:                                  
    case SIOCSIFNETMASK:                                  
    case SIOCGIFDSTADDR:                                  
    case SIOCSIFDSTADDR:                                  
    case SIOCSIFPFLAGS:                                   
    case SIOCGIFPFLAGS:                                   
    case SIOCSIFFLAGS:                                    
        err = devinet_ioctl(net, cmd, (void __user *)arg);
        break;                                            
    default:                                              
        if (sk->sk_prot->ioctl)                           
            err = sk->sk_prot->ioctl(sk, cmd, arg);       
        else                                              
            err = -ENOIOCTLCMD;                           
        break;                                            
    }                                                     
    return err;                                           
}                                                         
EXPORT_SYMBOL(inet_ioctl);                                
```

根据选项的不同，再分别调用不同的处理函数 `ip_rt_ioctl` ， `arp_ioctl` ， `devinet_ioctl` ， `sk->sk_prot->ioctl` ，其中 `sk->sk_prot->ioctl` 调用的函数是套接字类型对应的 `inetsw_array[]` 的 `ioctl` 成员变量（如，tcp 对应的就是 `tcp_ioctl` ）。

其中 `devinet_ioctl` 用来处理和网卡相关的操作选项，比如掩码（ SIOCSIFNETMASK ）、地址（ SIOCGIFADDR ）等：

```
int devinet_ioctl(struct net *net, unsigned int cmd, void __user *arg
{
    struct ifreq ifr;
    struct sockaddr_in sin_orig;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    struct in_device *in_dev;
    struct in_ifaddr **ifap = NULL;
    struct in_ifaddr *ifa = NULL;
    struct net_device *dev;
    char *colon;
    int ret = -EFAULT;
    int tryaddrmatch = 0;

    /*
     *  Fetch the caller's info block into kernel space
     */

    if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))
        goto out;
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    /* save original address for comparison */
    memcpy(&sin_orig, sin, sizeof(*sin));

    colon = strchr(ifr.ifr_name, ':');
    if (colon)
        *colon = 0;

    dev_load(net, ifr.ifr_name);

    switch (cmd) {
    case SIOCGIFADDR:   /* Get interface address */
    case SIOCGIFBRDADDR:    /* Get the broadcast address */
    case SIOCGIFDSTADDR:    /* Get the destination address */
    case SIOCGIFNETMASK:    /* Get the netmask for the interface */
        /* Note that these ioctls will not sleep,
           so that we do not impose a lock.
           One day we will be forced to put shlock here (I mean SMP)
         */
        tryaddrmatch = (sin_orig.sin_family == AF_INET);
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        break;

    case SIOCSIFFLAGS:
        ret = -EPERM;
        if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
            goto out;
        break;
    case SIOCSIFADDR:   /* Set interface address (and family) */
    case SIOCSIFBRDADDR:    /* Set the broadcast address */
    case SIOCSIFDSTADDR:    /* Set the destination address */
    case SIOCSIFNETMASK:    /* Set the netmask for the interface */
        ret = -EPERM;
        if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
            goto out;
        ret = -EINVAL;
        if (sin->sin_family != AF_INET)                            
            goto out;                                              
        break;                                                     
    default:                                                       
        ret = -EINVAL;                                             
        goto out;                                                  
    }                                                              
                                                                   
    rtnl_lock();                                                   
                                                                   
    ret = -ENODEV;                                                 
    dev = __dev_get_by_name(net, ifr.ifr_name);                    
    if (!dev)                                                      
        goto done;                                                 
                                                                   
    if (colon)                                                     
        *colon = ':';                                              
                                                                   
    in_dev = __in_dev_get_rtnl(dev);                               
    if (in_dev) {                                                  
        if (tryaddrmatch) {                                        
            /* Matthias Andree */                                  
            /* compare label and address (4.4BSD style) */         
            /* note: we only do this for a limited set of ioctls   
               and only if the original address family was AF_INET.
               This is checked above. */                           
            for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;  
                 ifap = &ifa->ifa_next) {                          
                if (!strcmp(ifr.ifr_name, ifa->ifa_label) &&       
                    sin_orig.sin_addr.s_addr ==                    
                            ifa->ifa_local) {                      
                    break; /* found */                             
                }                                                  
            }                                                      
        }                                                          
        /* we didn't get a match, maybe the application is         
           4.3BSD-style and passed in junk so we fall back to      
           comparing just the label */                             
        if (!ifa) {                                                
            for (ifap = &in_dev->ifa_list; (ifa = *ifap) != NULL;  
                 ifap = &ifa->ifa_next)                            
                if (!strcmp(ifr.ifr_name, ifa->ifa_label))         
                    break;                                         
        }                                                          
    }                                                              
                                                                   
    ret = -EADDRNOTAVAIL;                                          
    if (!ifa && cmd != SIOCSIFADDR && cmd != SIOCSIFFLAGS)         
        goto done;                                                 
                                                                   
    switch (cmd) {                                                 
    case SIOCGIFADDR:   /* Get interface address */                
        sin->sin_addr.s_addr = ifa->ifa_local;                     
        goto rarok;                                                
                                                                   
    case SIOCGIFBRDADDR:    /* Get the broadcast address */        
        sin->sin_addr.s_addr = ifa->ifa_broadcast;                 
        sin->sin_addr.s_addr = ifa->ifa_broadcast;                 
        goto rarok;                                                
                                                                   
    case SIOCGIFDSTADDR:    /* Get the destination address */      
        sin->sin_addr.s_addr = ifa->ifa_address;                   
        goto rarok;                                                
                                                                   
    case SIOCGIFNETMASK:    /* Get the netmask for the interface */
        sin->sin_addr.s_addr = ifa->ifa_mask;                      
        goto rarok;                                                
                                                                   
    case SIOCSIFFLAGS:                                             
        if (colon) {                                               
            ret = -EADDRNOTAVAIL;                                  
            if (!ifa)                                              
                break;                                             
            ret = 0;                                               
            if (!(ifr.ifr_flags & IFF_UP))                         
                inet_del_ifa(in_dev, ifap, 1);                     
            break;                                                 
        }                                                          
        ret = dev_change_flags(dev, ifr.ifr_flags);                
        break;                                                     
                                                                   
    case SIOCSIFADDR:   /* Set interface address (and family) */   
        ret = -EINVAL;                                             
        if (inet_abc_len(sin->sin_addr.s_addr) < 0)                
            break;                                                 
                                                                   
        if (!ifa) {                                                
            ret = -ENOBUFS;                                        
            ifa = inet_alloc_ifa();                                
            if (!ifa)                                              
                break;                                             
            INIT_HLIST_NODE(&ifa->hash);                           
            if (colon)                                             
                memcpy(ifa->ifa_label, ifr.ifr_name, IFNAMSIZ);    
            else                                                   
                memcpy(ifa->ifa_label, dev->name, IFNAMSIZ);       
        } else {                                                   
            ret = 0;                                               
            if (ifa->ifa_local == sin->sin_addr.s_addr)            
                break;                                             
            inet_del_ifa(in_dev, ifap, 0);                         
            ifa->ifa_broadcast = 0;                                
            ifa->ifa_scope = 0;                                    
        }                                                          
                                                                   
        ifa->ifa_address = ifa->ifa_local = sin->sin_addr.s_addr;  
                                                                   
        if (!(dev->flags & IFF_POINTOPOINT)) {                     
            ifa->ifa_prefixlen = inet_abc_len(ifa->ifa_address);   
            ifa->ifa_mask = inet_make_mask(ifa->ifa_prefixlen);    
            if ((dev->flags & IFF_BROADCAST) &&                    
                ifa->ifa_prefixlen < 31)                           
                ifa->ifa_broadcast = ifa->ifa_address |            
                             ~ifa->ifa_mask;                       
       } else {
           ifa->ifa_prefixlen = 32;
           ifa->ifa_mask = inet_make_mask(32);
       }
       set_ifa_lifetime(ifa, INFINITY_LIFE_TIME, INFINITY_LIFE_TIME);
       ret = inet_set_ifa(dev, ifa);
       break;

   case SIOCSIFBRDADDR:    /* Set the broadcast address */
       ret = 0;
       if (ifa->ifa_broadcast != sin->sin_addr.s_addr) {
           inet_del_ifa(in_dev, ifap, 0);
           ifa->ifa_broadcast = sin->sin_addr.s_addr;
           inet_insert_ifa(ifa);
       }
       break;

   case SIOCSIFDSTADDR:    /* Set the destination address */
       ret = 0;
       if (ifa->ifa_address == sin->sin_addr.s_addr)
           break;
       ret = -EINVAL;
       if (inet_abc_len(sin->sin_addr.s_addr) < 0)
           break;
       ret = 0;
       inet_del_ifa(in_dev, ifap, 0);
       ifa->ifa_address = sin->sin_addr.s_addr;
       inet_insert_ifa(ifa);
       break;

   case SIOCSIFNETMASK:    /* Set the netmask for the interface */

       /*
        *  The mask we set must be legal.
        */
       ret = -EINVAL;
       if (bad_mask(sin->sin_addr.s_addr, 0))
           break;
       ret = 0;
       if (ifa->ifa_mask != sin->sin_addr.s_addr) {
           __be32 old_mask = ifa->ifa_mask;
           inet_del_ifa(in_dev, ifap, 0);
           ifa->ifa_mask = sin->sin_addr.s_addr;
           ifa->ifa_prefixlen = inet_mask_len(ifa->ifa_mask);

           /* See if current broadcast address matches
            * with current netmask, then recalculate
            * the broadcast address. Otherwise it's a
            * funny address, so don't touch it since
            * the user seems to know what (s)he's doing...
            */
           if ((dev->flags & IFF_BROADCAST) &&
               (ifa->ifa_prefixlen < 31) &&
               (ifa->ifa_broadcast ==
                (ifa->ifa_local|~old_mask))) {
               ifa->ifa_broadcast = (ifa->ifa_local |
                             ~sin->sin_addr.s_addr);
            }
            inet_insert_ifa(ifa);
        }
        break;
    }
done:
    rtnl_unlock();
out:
    return ret;
rarok:
    rtnl_unlock();
    ret = copy_to_user(arg, &ifr, sizeof(struct ifreq)) ? -EFAULT : 0;
    goto out;
}
```

而 `dev_ioctl` 则是针对所有 IO 接口的各种操作。

`net/core/dev_ioctl.c`

```
/*
 *  This function handles all "interface"-type I/O control requests. The actual
 *  'doing' part of this is dev_ifsioc above.
 */
/**                                                                   
 *  dev_ioctl   -   network device ioctl                              
 *  @net: the applicable net namespace                                
 *  @cmd: command to issue                                            
 *  @arg: pointer to a struct ifreq in user space                     
 *                                                                    
 *  Issue ioctl functions to devices. This is normally called by the  
 *  user space syscall interfaces but can sometimes be useful for     
 *  other purposes. The return value is the return from the syscall if
 *  positive or a negative errno code on error.                       
 */                                                                   
                                                                      
int dev_ioctl(struct net *net, unsigned int cmd, void __user *arg)    
{                                                                     
    struct ifreq ifr;                                                 
    int ret;                                                          
    char *colon;                                                      
                                                                      
    /* One special case: SIOCGIFCONF takes ifconf argument            
       and requires shared lock, because it sleeps writing            
       to user space.                                                 
     */                                                               
                                                                      
    if (cmd == SIOCGIFCONF) {                                         
        rtnl_lock();                                                  
        ret = dev_ifconf(net, (char __user *) arg);                   
        rtnl_unlock();                                                
        return ret;                                                   
    }                                                                 
    if (cmd == SIOCGIFNAME)                                           
        return dev_ifname(net, (struct ifreq __user *)arg);           
                                                                      
    if (copy_from_user(&ifr, arg, sizeof(struct ifreq)))              
        return -EFAULT;                                               
    ifr.ifr_name[IFNAMSIZ-1] = 0;                       
                                                        
    colon = strchr(ifr.ifr_name, ':');                  
    if (colon)                                          
        *colon = 0;                                     
                                                        
    /*                                                  
     *  See which interface the caller is talking about.
     */                                                 
                                                        
    switch (cmd) {                                      
    /*                                                  
     *  These ioctl calls:                              
     *  - can be done by all.                           
     *  - atomic and do not require locking.            
     *  - return a value                                
     */                                                 
    case SIOCGIFFLAGS:                                  
    case SIOCGIFMETRIC:                                 
    case SIOCGIFMTU:                                    
    case SIOCGIFHWADDR:                                 
    case SIOCGIFSLAVE:                                  
    case SIOCGIFMAP:                                    
    case SIOCGIFINDEX:                                  
    case SIOCGIFTXQLEN:                                 
        dev_load(net, ifr.ifr_name);                    
        rcu_read_lock();                                
        ret = dev_ifsioc_locked(net, &ifr, cmd);        
        rcu_read_unlock();                              
        if (!ret) {                                     
            if (colon)                                  
                *colon = ':';                           
            if (copy_to_user(arg, &ifr,                 
                     sizeof(struct ifreq)))             
                ret = -EFAULT;                          
        }                                               
        return ret;                                     
        return ret;                                  
                                                     
    case SIOCETHTOOL:                                
        dev_load(net, ifr.ifr_name);                 
        rtnl_lock();                                 
        ret = dev_ethtool(net, &ifr);                
        rtnl_unlock();                               
        if (!ret) {                                  
            if (colon)                               
                *colon = ':';                        
            if (copy_to_user(arg, &ifr,              
                     sizeof(struct ifreq)))          
                ret = -EFAULT;                       
        }                                            
        return ret;                                  
                                                     
    /*                                               
     *  These ioctl calls:                           
     *  - require superuser power.                   
     *  - require strict serialization.              
     *  - return a value                             
     */                                              
    case SIOCGMIIPHY:                                
    case SIOCGMIIREG:                                
    case SIOCSIFNAME:                                
        if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
            return -EPERM;                           
        dev_load(net, ifr.ifr_name);                 
        rtnl_lock();                                 
        ret = dev_ifsioc(net, &ifr, cmd);            
        rtnl_unlock();                               
        if (!ret) {                                  
            if (colon)                               
                *colon = ':';                        
            if (copy_to_user(arg, &ifr,              
                     sizeof(struct ifreq)))          
                ret = -EFAULT;                       
        } 
    /*                                               
     *  These ioctl calls:                           
     *  - require superuser power.                   
     *  - require strict serialization.              
     *  - do not return a value                      
     */                                              
    case SIOCSIFMAP:                                 
    case SIOCSIFTXQLEN:                              
        if (!capable(CAP_NET_ADMIN))                 
            return -EPERM;                           
        /* fall through */                           
    /*                                               
     *  These ioctl calls:                           
     *  - require local superuser power.             
     *  - require strict serialization.              
     *  - do not return a value                      
     */                                              
    case SIOCSIFFLAGS:                               
    case SIOCSIFMETRIC:                              
    case SIOCSIFMTU:                                 
    case SIOCSIFHWADDR:                              
    case SIOCSIFSLAVE:                               
    case SIOCADDMULTI:                               
    case SIOCDELMULTI:                               
    case SIOCSIFHWBROADCAST:                         
    case SIOCSMIIREG:                                
    case SIOCBONDENSLAVE:                            
    case SIOCBONDRELEASE:                            
    case SIOCBONDSETHWADDR:                          
    case SIOCBONDCHANGEACTIVE:                       
    case SIOCBRADDIF:                                
    case SIOCBRDELIF:                                
    case SIOCSHWTSTAMP:                              
        if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
            return -EPERM;                           
        /* fall through */                           
    case SIOCBONDSLAVEINFOQUERY:                     
    case SIOCBONDINFOQUERY:                          
        dev_load(net, ifr.ifr_name);                           
        rtnl_lock();                                           
        ret = dev_ifsioc(net, &ifr, cmd);                      
        rtnl_unlock();                                         
        return ret;                                            
                                                               
    case SIOCGIFMEM:                                           
        /* Get the per device memory space. We can add this but
         * currently do not support it */                      
    case SIOCSIFMEM:                                           
        /* Set the per device memory buffer space.             
         * Not applicable in our case */                       
    case SIOCSIFLINK:                                          
        return -ENOTTY;                                        
                                                               
    /*                                                         
     *  Unknown or private ioctl.                              
     */                                                        
    default:                                                   
        if (cmd == SIOCWANDEV ||                               
            cmd == SIOCGHWTSTAMP ||                            
            (cmd >= SIOCDEVPRIVATE &&                          
             cmd <= SIOCDEVPRIVATE + 15)) {                    
            dev_load(net, ifr.ifr_name);                       
            rtnl_lock();                                       
            ret = dev_ifsioc(net, &ifr, cmd);                  
            rtnl_unlock();                                     
            if (!ret && copy_to_user(arg, &ifr,                
                         sizeof(struct ifreq)))                
                ret = -EFAULT;                                 
            return ret;                                        
        }                                                      
        /* Take care of Wireless Extensions */                 
        if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST)           
            return wext_handle_ioctl(net, &ifr, cmd, arg);     
        return -ENOTTY;                                        
    }
}
```

