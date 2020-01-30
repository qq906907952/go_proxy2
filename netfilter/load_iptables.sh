#!/bin/bash
set -e 

server_addr_v4=(99.99.99.99 11.11.11.11)
server_addr_v6=()
cd "$(dirname "$0")"

##ipv4##
ipset create local hash:net

for i in ${server_addr_v4[@]} ; do ipset add local $i  ; done;

for i in `cat ../china_ipv4` ; do  ipset add local $i ; done;

iptables-restore iptables.save

ip rule add fwmark 0x1 table 100
ip route add local default dev lo table 100


##ipv6##
ipset create ipv6_whitelist hash:net family inet6

for i in `cat ../ipv6_white_list` ; do  ipset add ipv6_whitelist $i ; done;

for i in ${server_addr_v6[@]} ; do ipset add ipv6_whitelist $i  ; done;

ip6tables-restore ip6tables.save

ip -6 rule add fwmark 0x1 table 100
ip -6 route add local default dev lo table 100

	

