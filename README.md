The SB6183 cable modem randomly drops TCP packets with the TCP Timestamp option set.  This netfilter module works around that by setting TCP Timestamp option to TCP option 253 (experimental).

to make the kernel module, set KDIR makefile variable, then "make"

to make the ip6tables module, set IPTABLES\_SRC makefile variable, then "make libxt\_SB6183.so" the result goes in /lib\*/xtables/

Testing sending 50 tcp syn packets to 3 different networks:

	timestamp set in header, using -j TCPOPTSTRIP --strip-options timestamp: 40/150 Lost
	timestamp set in header, using -j SB6183: 2/150 Lost
	timestamp not set in header: 2/150 Lost
