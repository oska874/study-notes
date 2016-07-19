---
tags : [ net , kernel , Linux ]
---


<!-- MarkdownTOC -->

- 1. 创建套接字（`socket`）
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


## 2. 连接（`connect`）


## 3. 绑定（`bind`）


## 4. 发送

send ， sendto

tcp ， udp

## 5. 接收

recv ， recvfrom

tcp ， udp

## 6. 关闭连接（`close`）
