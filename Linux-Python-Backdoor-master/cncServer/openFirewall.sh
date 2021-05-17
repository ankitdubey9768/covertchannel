#!/usr/bin/env bash
# reset all tables, delete any user defined chains and zero counters
for table in filter nat mangle; do
iptables -t $table -F
iptables -t $table -X
iptables -t $table -Z; done

# set default policies to ACCEPT
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT