#!/bin/bash 

set -e

server_addr_v4=(99.99.99.99 11.11.11.11 )
server_addr_v6=()

cd "$(dirname "$0")"

nft add table ip go_proxy 

nft add set ip go_proxy  ipv4_whitelist \{type ipv4_addr\; flags constant,interval\;\}

for i in `cat ../china_ipv4`; do nft add element go_proxy ipv4_whitelist \{ $i \}  ; done;

for i in ${server_addr_v4[@]} ; do nft add element go_proxy ipv4_whitelist \{ $i \}  ; done;


nft list set go_proxy ipv4_whitelist > nft_set_ipv4.save

sed  -i '1d' nft_set_ipv4.save
sed  -i '$d' nft_set_ipv4.save

nft -I . -f nft_ipv4.save

rm nft_set_ipv4.save

ip rule add fwmark 0x1 table 100
ip route add local default dev lo table 100

nft add table ip6 go_proxy_ipv6

nft add set ip6 go_proxy_ipv6  ipv6_whitelist \{type ipv6_addr\; flags constant,interval \; auto-merge auto-merge \; \}

for i in `cat ../ipv6_white_list`; do  nft add element ip6 go_proxy_ipv6 ipv6_whitelist \{ $i \}  ; done;

for i in ${server_addr_v6[@]} ; do  nft add element ip6 go_proxy_ipv6 ipv6_whitelist \{ $i \}  ; done;
	
nft list set ip6 go_proxy_ipv6 ipv6_whitelist > nft_set_ipv6.save

sed  -i '1d' nft_set_ipv6.save
sed  -i '$d' nft_set_ipv6.save

nft -I . -f nft_ipv6.save

rm nft_set_ipv6.save

ip -6 rule add fwmark 0x1 table 100
ip -6 route add local default dev lo table 100
