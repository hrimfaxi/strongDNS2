#!/bin/bash

nft delete table inet douyin >/dev/null 2>&1
nft delete table inet youtube >/dev/null 2>&1

# Douyin: 对短视频IP基于80%的丢包
nft -f - <<EOF
table inet douyin {
	set spam_ips {
		type ipv4_addr
		timeout 1h
		flags timeout, dynamic
	}
	set spam_ips6 {
		type ipv6_addr
		timeout 1h
		flags timeout, dynamic
	}

	chain prerouting {
		type filter hook prerouting priority -200; policy accept;

		ip saddr @spam_ips add @spam_ips  { ip  saddr timeout 1h } numgen random mod 100 < 80 counter drop
		ip6 saddr @spam_ips6 add @spam_ips6 { ip6 saddr timeout 1h } numgen random mod 100 < 80 counter drop
	}
}
EOF

# Youtube: 对youtube QUIC直接封禁(避免有缺陷的QUIC拖慢翻墙速度)
nft -f - <<EOF
table inet youtube {
	set spam_ips {
		type ipv4_addr
		timeout 1h
		flags timeout, dynamic
	}
	set spam_ips6 {
		type ipv6_addr
		timeout 1h
		flags timeout, dynamic
	}

	chain prerouting {
		type filter hook prerouting priority -100; policy accept;

		udp sport 443 ip   saddr @spam_ips  counter drop
		udp sport 443 ip6  saddr @spam_ips6 counter drop
		udp dport 443 ip   daddr @spam_ips  counter reject
		udp dport 443 ip6  daddr @spam_ips6 counter reject
	}
}
EOF
