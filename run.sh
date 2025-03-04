#!/bin/sh

dns_server="{1.1.1.1, 8.8.8.8}"

sudo nft delete table strongDNS2 > /dev/null 2>&1
sudo nft add table strongDNS2
sudo nft add chain ip strongDNS2 input "{ type filter hook input priority 0 ; } "
sudo nft add rule strongDNS2 input ip saddr $dns_server udp sport 53 counter queue num 1
sudo ./strongDNS2
