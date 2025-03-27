# 网络空间信息安全审计系统设计与实现

## 1. 介绍

本系统使用cgo调用C语言的libnids库实现网络空间安全审计功能。

## 2. 编译运行

在项目根目录执行

```bash
go run .
```

编译为二进制文件

```bash
go build .
```

## 3. 系统用法

```bash
Usage of websafe
  -d string
        设备名称 (default "eth0")
  -f string
        BPF过滤规则
  -m int
        运行模式：1. http 2. ethernet 3. 扫描攻击检测 (default 1)
```