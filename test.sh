#!/bin/sh

DNS=8.8.8.8
dig news.163.com @$DNS
dig reddit.com @$DNS
dig rule34.xxx @$DNS
dig www.youtube.com @$DNS
dig www.google.com @$DNS
dig google.com @$DNS # 非压缩域名

# ipv6
dig reddit.com AAAA @$DNS
dig rule34.xxx AAAA @$DNS
