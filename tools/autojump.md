
install:

```
sudo apt-get install autojump
```

usage:

配合 oh-my-zsh 很好用（修改 `~/.zshrc` , 添加内容 `plugins=(autojump )`），安装了 oh-my-zsh 之后会把 autojump 重命名为 `j` , 可以这样使用：

```
➜  /os_dev  pwd
/os_dev
➜  /os_dev  j workspace
/os_dev/workspace
➜  workspace  pwd
/os_dev/workspace
➜  workspace
```

也可以使用 autojump 的自动补全功能，选择自己的目标路径即可（此时配合oh-my-zsh 效果更佳，比 bash 更合适）

```
➜  workspace  j wo__
wo__1__/os_dev/workspace/WebResource/cag_web                              wo__3__/os_dev/workspace/WebResource/cag_web/site
wo__2__/os_dev/workspace/test/ccc                                         wo__4__/os_dev/workspace/WebResource 
```

问题：
  在 oh-my-zsh 环境下， 直接使用autojump 命令本身反而有问题，不能用，原因不详
