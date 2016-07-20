
<!-- MarkdownTOC -->

- 启动脚本
- 配置参数：
- 安装软件
    - pact
    - 直接安装

<!-- /MarkdownTOC -->


### 启动脚本

babun.bat

rebase.bat

update.bat

以 zsh 作为 shell 启动 babun ：

`%userprofile%\.babun\cygwin\bin\mintty.exe /bin/env CHERE_INVOKING=1 /bin/zsh.exe`

### 配置参数：

`C:\Users\<user>\.babun\cygwin\usr\local\etc`

支持 bash 和 zsh

oh-my-zsh

### 安装软件

#### pact

#### 直接安装

autojump

```
git clone git://github.com/joelthelion/autojump.git
cd autojump
./install.py
```

pip

```
wget https://bootstrap.pypa.io/get-pip.py -O - | python
```

cheat

```
pip install cheat
cheat xxx
```

```
#安装tmux
pact install tmux        

#安装screen
pact install screen

#安装zip
pact install zip

#安装svn
pact install subversion

#安装lftp命令
pact install lftp

#安装p7zip命令
pact install p7zip

#基于openssh的socks https代理
pact install connect-proxy

#安装linux基础命令行工具more/col/whereis等命令
pact install util-linux    

#安装dig命令
pact install bind-utils

#安装Telnet等常用网络命令
pact install inetutils  

#安装python环境
pact install python        
pact install python-crypto
```