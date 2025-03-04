#!/bin/bash

query_count=10000
result=unique_records_ipv6.txt
log=log_ipv6.txt
type=AAAA
# 向1.1.1.4/8.8.8.9发送dns请求（是无效的dns服务器，但gfw会上当回应）
dnsserver=8.8.8.9
site=8964.zh.wikipedia.org

for ((i = 1; i <= query_count; i++)); do
	dig $site $type @$dnsserver | grep "^$site\." | awk '{print $5}' >>$log
	echo -ne "Progress: $((i * 100 / query_count))% \r"
done

sort -u $log >$result
echo $result generated $(wc -l $result) entries
