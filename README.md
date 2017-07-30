# strongDNS
排除 GFW DNS 污染的小工具

## 安装

###编译

依赖的库: libnetfilter_queue

    make
    
###运行
    
    run.sh
    
默认支持的 DNS server 为 8.8.8.8
修改 run.sh 下的 dns_server 字段即可添加 server
    
##原理

GFW 发送过来的 DNS 包 Additional RRs(额外资源记录数) 通常为 0 ,而支持 EDNS 扩展的 DNS 服务器通常不为 0. 过滤掉 Additional RRs 为 0 的 包即可.
    


