
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
