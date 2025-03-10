# strongDNS2
排除(2025年版本的)`GFW` `DNS`污染的小工具。可以在`openwrt`/`linux`下运行。

## DNS污染

`GFW`（`Great Firewall`，中国国家防火墙）的`DNS`污染是一种常见的网络干扰手段，它通过向用户的`DNS`查询注入错误的响应来阻止访问特定的域名。
例如，用户尝试访问受限网站时，`GFW`会返回假的IP地址或根本不可达的地址，导致用户无法正常连接到目标网站。
随着`IPv6`的普及，`GFW`的`DNS`污染手段也在升级，开始针对 `IPv6` 地址进行干扰。

## 系统要求
- `Linux`内核: 2.6.32以上
- 依赖库: `libnetfilter_queue`、`libnfnetlink`、`libmnl`

## 特性

* 支持应对2025年的`GFW` `dns`污染，包括不同格式的`A`记录回应(带压缩标记/完整域名)
* 支持`openwrt`
* 由于本程序需要使用网络管理员权限，提供以下安全性加固：
  * 支持使用`openwrt`的`ujail`加固沙盒防御恶意攻击
  * 支持编译器加固，如`RELRO`，`Stack canary`，`PIE`等
* 支持过滤`A`/`AAAA`记录的污染记录
* 支持过滤`IPv4`/`IPv6`的DNS服务器回应
* 支持从`IPv4`/`IPv6`列表文件中读取记录进行过滤，可以应对未来`GFW`升级

## 编译

[编译方法](./compile.md)

## 安装

`openwrt`:

复制编译输出结果`output`目录里的所有文件到`openwrt`路由器上。如下图所示：

```
├── etc
│   ├── capabilities
│   │   └── strongDNS2.json
│   └── init.d
│       └── strongDNS2
└── usr
    ├── bin
    │   └── strongDNS2
    └── share
        └── strongDNS2
            ├── ipv4.txt
            └── ipv6.txt
```

然后`ssh`到`openwrt`:
```sh
opkg update
opkg install kmod-nft-queue libnetfilter-queue1
service strongDNS2 enable
service strongDNS2 start
```

## FAQ

Q: 为什么无法运行`strongDNS2`\
A: 检查`openwrt`是否安装了
```sh
opkg install kmod-nft-queue libnetfilter-queue1
```

检查列表文件是否存在：
```sh
ls -l /usr/share/strongDNS2/ipv[46].txt
```

Q: 如何检查是否生效？\
A: 在电脑/`openwrt`路由器上，使用`dig`/`nslookup`测试:

`dig`:
```sh
dig reddit.com @8.8.8.8
dig google.com @8.8.8.8
dig www.google.com @8.8.8.8
dig wikipedia.org @8.8.8.8
dig youtube.com @8.8.8.8
```
`nslookup`:
```sh
nslookup reddit.com 8.8.8.8
nslookup google.com 8.8.8.8
nslookup www.google.com 8.8.8.8
nslookup wikipedia.org 8.8.8.8
nslookup youtube.com 8.8.8.8
```


如果你看到的以上域名解析IP不在[污染列表](https://zh.wikiversity.org/wiki/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93IP%E5%88%97%E8%A1%A8#IPv6)中，恭喜你的`strongDNS2`已经生效了。

Q: 为什么没有生效?\
A: 从路由器到电脑检查`DNS`服务器，必须为*国际`DNS`*，如以下：

`IPv4`:
```
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
208.67.222.222
185.222.222.222
45.11.45.11
149.112.112.112
```

`IPv6`:
```
2606:4700:4700::1111
2606:4700:4700::1001
2001:4860:4860::8888
2001:4860:4860::8844
2620:fe::fe,2620:fe::9
```

推荐电脑使用路由器`IP`作为`DNS`以免混乱。

清空你的电脑的`DNS`缓存：

```bat
ipconfig /reflushdns
```

清空你的`openwrt` `dnsmasq`缓存：
```sh
killall -1 dnsmasq
```

检查你的`openwrt`日志：
```sh
logread
```

Q: 已经生效了，可我还是不能上谷歌/`youtube`/外网？\
A: 除了`DNS`污染`GFW`还有其它防火墙，你需要比如`xray`任意门(`tproxy`)等程序做透明代理到外网。

Q: 那我为什么还需要使用`strongDNS2`防御`dns`污染？而是不直接上`xray`任意门？\
A: `xray`任意门(`tproxy`)对`dns`需要劫持到`xray`中再使用`xray`自带的`dns`服务器进行缓存，过滤，转发远程服务器。有几个问题：

* 配置困难
  * 普通用户很难理解`tproxy`复杂的`dns`劫持流程
  * 稍不注意(忘记设置`dns-out`，忘记设置`fwmark`)就会形成`dns` `udp`环路，轻则`cpu`占用100%，重则直接路由器耗尽内存重启
* 复杂的流程
  * `xray`劫持`dns`的流程包括:
    * 转发/输出链中设置`fwmark1`
    * 被标记`fwmark1`包经过`ip`策略路由转发环回接口
    * 环回接口中被`nft`/`iptables`透明路由规则发送到`xray`任意门端口
    * 在`xray`中被`dns-out`路由规则匹配
    * 如果有`dns`缓存，先使用缓存返回。
    * 使用`dns`规则，选择一个远程`dns`服务器发送到对端
    * 发送对端时必须设置`fwmark2`避免环形
* 如此复杂的解析流程造成了：
  * 有时异常高的解析时间
  * 调试`xray`配置错误浪费时间
  * 复杂的网络环境比如`p2p`下载流量造成路由器贫弱`cpu`上的`xray`不堪重负

作为对比, `strongDNS2`可以做到开箱即用。使用者只需要2步即可享受没有`DNS`污染的上网环境：
- `openwrt`路由器设置使用国际`dns`: `8.8.8.8`，或者`1.1.1.1`等。
- `openwrt`开启`strongDNS2`服务，它自动过滤来自知名国际`DNS`服务器的`GFW`污染包

Q: 我同时使用`xray`任意门和`strongDNS2`吗？\
A: 当然可以！对以下[xray任意门](https://github.com/XTLS/Xray-docs-next/blob/main/docs/document/level-2/tproxy_ipv4_and_ipv6.md)
教程，需要去掉它对`dns`的劫持：
修改以下规则:
```
# prerouting链
meta l4proto { tcp, udp } meta mark set 0x00000001 tproxy ip to 127.0.0.1:12345 accept
meta l4proto { tcp, udp } meta mark set 0x00000001 tproxy ip6 to [::1]:12345 accept

# output链
meta l4proto { tcp, udp } meta mark set 0x00000001 accept
```

为不要劫持`udp`流量:
```
# prerouting链
meta l4proto tcp meta mark set 0x00000001 tproxy ip to 127.0.0.1:12345 accept
meta l4proto tcp meta mark set 0x00000001 tproxy ip6 to [::1]:12345 accept

# output链
meta l4proto tcp meta mark set 0x00000001 accept
```

这样`strongDNS2`和`xray`任意门就可以共同抵御`DNS`污染。而不是`xray`任意门劫持路由器的一切`UDP`流量。

## 原理

`GFW`是通过“注射器”抢在正常`DNS`回应前先返回污染`A`/`AAAA`记录响应给你的路由器/主机造成`DNS`污染。可以通过深度`DPI`技术过滤掉这些污染包从而达到清除污染的目的。
~~GFW 发送过来的 DNS 包 Additional RRs(额外资源记录数) 通常为 0 ,而支持 EDNS 扩展的 DNS 服务器通常不为 0. 过滤掉 Additional RRs 为 0 的 包即可.~~
到了2025年`GFW`提高了检测难度。现在需要自行解析`A`/`AAAA`记录过滤掉已知的污染IP。`strongDNS2`现在读取`DNS`污染`IPv4`/`IPv6`列表文件工作，以及一个简单的过滤器过滤2001::1这样的`IPv6`污染地址。

### `A`记录回应格式

对不同的域名，比如`google.com`/`www.google.com`，`GFW`回应污染包可能使用或不使用压缩选项。例如：
```sh
dig www.google.com @8.8.8.8
```

```
answer_section
00000000  c0 0c 00 01 00 01 00 00  00 51 00 04 c7 10 9e 0c  |.........Q......|
```

有压缩选项。

```sh
dig google.com @8.8.8.8
```

`GFW`回应污染包:

```
answer_section
00000000  06 67 6f 6f 67 6c 65 03  63 6f 6d 00 00 01 00 01  |.google.com.....|
00000010  00 00 00 3c 00 04 3b 18  03 ae                    |...<..;...      |
```

没有压缩选项。对于以上两种情况，`strongDNS2`都可以处理。

### `IPv6`

目前`GFW`对`AAAA`记录的污染，可能返回两种`IP`:

* `2001::xxxx:yyyy`
* `2a03:2880:f10d:83:face:b00c:0:25de`

例如：

```sh
dig reddit.com @8.8.8.8 AAAA

IPv6: 2a03:2880:f117:83:face:b00c:0:25de polluted, dropping...
IPv6: 2001::c73b:9628 polluted, dropping...
```

有发送两个污染地址，都需要丢掉。

前者的`xxxx`/`yyyy`是随机生成的，通过一个检查函数可以轻松过滤。
而后者大约有几十个，使用列表过滤。 这样`strongDNS2`成功过滤了`GFW`对`AAAA`记录的污染。

### 鸣谢

* [strongDNS原作者](https://github.com/Sunnny-3n/strongDNS)
* [防火长城域名服务器缓存污染IP列表](https://zh.wikiversity.org/wiki/%E9%98%B2%E7%81%AB%E9%95%BF%E5%9F%8E%E5%9F%9F%E5%90%8D%E6%9C%8D%E5%8A%A1%E5%99%A8%E7%BC%93%E5%AD%98%E6%B1%A1%E6%9F%93IP%E5%88%97%E8%A1%A8#IPv6)
* [wallbreed](https://gfw.report/publications/ndss25/zh/)
* [xray-core](https://github.com/xtls/xray-core)
* [xray任意门教程](https://github.com/XTLS/Xray-docs-next/blob/main/docs/document/level-2/tproxy_ipv4_and_ipv6.md)
* [xxhash32](https://github.com/Cyan4973/xxHash)
