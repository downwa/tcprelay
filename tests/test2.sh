#!/bin/sh

TESTPORT=5000
TLOG=telnet.log

if [ -z "$1" ]; then
	echo "Usage: ./test2.sh host"
	echo "Do many connections on host (port 5000)"
	echo "Goal is to populate host's log. Suitable with a"
	echo "host running tcprelay in mirror mode."
	exit 1
fi

H="$1"

echo "Will do 300 connections on port 5000 on target host '$H'"
echo "Proceed? (y/N)"

read a;

if [ "$a" != "y" -a "$a" != "Y" ]; then
	echo "Aborting."
	exit 1
fi

echo "Starting test..."

echo "Telnet log" > $TLOG

# 1. Perform tests

for i in $(seq 1 300); do
	cat telnet-input.txt | telnet $H $TESTPORT >> $TLOG 2>&1
done

echo "Test done."

