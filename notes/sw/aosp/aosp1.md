###

直接使用 friendlyarm 在 github 上提供的 manifest.xml 下载代码时会因为 GFW 的原因下载失败，这时可以使用国内的源替代 google 的代码源，比如[清华的镜像][https://mirrors.tuna.tsinghua.edu.cn/]:

```
repo init -u https://github.com/friendlyarm/android_manifest.git -b nanopi2-lollipop-mr1 --repo-url=https://gerrit-google.tuna.tsinghua.edu.cn/git-repo
```

然后修改代码目录下的文件 `.repo/manifest.xml` ，替换：

```
<remote  name="aosp"
         fetch="https://android.googlesource.com/" />
```

为：

```
<remote  name="aosp"
         fetch="https://aosp.tuna.tsinghua.edu.cn/" />
```

然后再执行 `repo sync` 就可以正常下载代码了。



###

编译生成的镜像文件：

```
➜  friendly ls out/target/product/nanopi2
android-info.txt  cache           data          installed-files.txt  previous_build_config.mk  recovery  system
boot              cache.img       dex_bootjars  obj                  ramdisk.img               root      system.img
boot.img          clean_steps.mk  gen           partmap.txt          ramdisk-recovery.img      symbols   userdata.img
```

要用到的文件主要是： `cache.img` 、 `boot.img` 、 `partmap.txt` 、 `ramdisk.img` 、 `system.img`

###

使用 ubuntu 16.04 编译 android 5.1 时会出现错误 ：

```
...
libnativehelper/JniInvocation.cpp:165: error: unsupported reloc 43
libnativehelper/JniInvocation.cpp:165: error: unsupported reloc 43
...
```

查了 SO ，出错的原因是 aosp 自带的 ld 和 ubuntu 16.04 不兼容，需要用系统自带的 ld 替换 ：

```
cp /usr/bin/ld.gold prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.11-4.6/x86_64-linux/bin/ld
```

注： 使用 ubuntu 16.04 编译 android 6 的源码也会出现类似问题，只需要替换对应（ `glibc2.15` ）的 ld 即可。

###

nanopi2 很挑卡，最开始编译了 aosp 镜像之后使用工具烧写到 kinston 的 16g sd 卡之后，启动 uboot 报错 找不到内核 ，然后换了三星的 8G 卡就好了，太神奇了，官方也有推荐的 sd 卡。


###

```
➜  sd-fuse_nanopi2 git:(master) ✗ ls
android  android_1  android_me  fusing.sh  mkimage.sh  prebuilt  s5p4418-android-sd4g-20160820.img  tools
```
