---
tags : aosp 
category : [ TECH ]
---


0. 准备

    - sd卡（挑卡）
    - usb转串口线
    
1. 下载代码

工具链

```
git clone https://github.com/friendlyarm/prebuilts.git 
sudo mkdir -p /opt/FriendlyARM/toolchain 
sudo tar xf prebuilts/gcc-x64/arm-cortexa9-linux-gnueabihf-4.9.3.tar.xz -C /opt/FriendlyARM/toolchain/
```

uboot

```
git clone https://github.com/friendlyarm/uboot_nanopi2.git 

```

kernel

```
git clone https://github.com/friendlyarm/linux-3.4.y.git 
cd linux-3.4.y 
```

aosp

```
mkdir android && cd android 
repo init -u https://github.com/friendlyarm/android_manifest.git -b nanopi2-lollipop-mr1
 repo sync
```

工具

```
git clone https://github.com/friendlyarm/sd-fuse_nanopi2.git 
cd sd-fuse_nanopi2
```

2. 编译 u-boot

```
cd uboot_nanopi2 git checkout nanopi2-lollipop-mr1 
make s5p4418_nanopi2_config 
make CROSS_COMPILE=arm-linux-
```

3. 编译内核

```
git checkout nanopi2-lollipop-mr1
make nanopi2_android_defconfig 
touch .scmversion 
make uImage
```

4. 编译 aosp

bash

```
source build/envsetup.sh 
lunch aosp_nanopi2-userdebug 
make -j8
```

替换 ld
修改

5. 烧写镜像

拷贝镜像到目录，替换uboot

```
sudo ./fusing.sh /dev/sdx
```

6. 总结

挑卡
出错解决
