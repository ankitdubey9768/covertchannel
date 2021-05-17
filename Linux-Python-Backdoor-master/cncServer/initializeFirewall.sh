#!/usr/bin/env bash
# reset all tables, delete any user defined chains and zero counters
for table in filter nat mangle; do
iptables -t $table -F
iptables -t $table -X
iptables -t $table -Z; done

# set default policies to DROP except for outbound traffic
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

iptables -A INPUT -p tcp --dport 80 -m state --state ESTABLISHED,RELATED -j ACCEPT

