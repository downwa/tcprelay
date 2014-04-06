#!/bin/sh

TESTPORT=5000
TLOG=telnet.log

echo "Telnet log" > $TLOG

# 1. Perform tests

for i in $(seq 1 300); do
	cat telnet-input.txt | telnet maison-pclin $TESTPORT >> $TLOG 2>&1
done

