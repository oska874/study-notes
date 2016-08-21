

```
repo init
repo sync
```

1. 寻找 repo 的路径
2. 检查当前工程是否有 repo 仓库，没有的话则使用 `_Init` 从远程克隆一个
3. repo 脚本自带 repo 仓库，则从本地拷贝过来
4. 检查执行的 repo 脚本是否就处于一个 repo 仓库，如果是的话，后续就使用当前目录下的 `main.py` ，
5. 否则 `~/bin/repo` 调用 `/path/to/project/.repo/repo/main.py` 
6. 克隆子仓库


1. repo repo
2. manifest repo
3. 




_Repo 类

Project 类

Init 类

XmlManifest 类


1. download repo (py)
2. clone repo repo
3. get manifest repo
4. get android child repo



python

- gitconfig
- subprocess