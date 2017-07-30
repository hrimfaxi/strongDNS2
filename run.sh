dns_server="{8.8.8.8}"

sudo nft add table strongDNS   
sudo nft add chain ip strongDNS input "{ type filter hook input priority 0 ; } " 
sudo nft add rule strongDNS input ip saddr $dns_server udp sport 53 queue num 1
sudo ./strongDNS
