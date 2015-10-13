ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m  := xt_SB6183.o

else
# normal makefile
KDIR = ../linux
IPTABLES_SRC = ../iptables

.PHONY: default clean

default:
	$(MAKE) -C $(KDIR) M=$$PWD 

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

libxt_SB6183.so: libxt_SB6183.c
	gcc -fPIC -shared -o libxt_SB6183.so -I $(IPTABLES_SRC)/include/ libxt_SB6183.c 

endif
