#!/bin/sh

PRG=../src/tcprelay
TESTPORT=9999
TLOG=/dev/null

echo "Telnet log" > $TLOG

# 1. Start server

$PRG -m -p $TESTPORT -n --telnet --test-mode 1 &

# 2. Perform tests

for i in $(seq 1 100); do
	cat telnet-input.txt | telnet localhost $TESTPORT >> $TLOG 2>&1
done

# 3. Tests finished, now we stop the server and check it was stopped successfully

kill `pgrep tcprelay`

T=checknoserverleft.tmp
REF=srvstoppedok
telnet localhost $TESTPORT > $T 2>&1
cmp $T $REF > /dev/null 2>&1
if [ "$?" -ne "0" ]; then
	echo "WARNING, TCPRELAY SERVER STILL RUNNING"
else
#  echo "tcprelay server stopped successfully"
	rm $T
fi

