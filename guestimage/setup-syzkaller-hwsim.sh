#!/bin/bash
ip link set dev wlan0 address 08:02:11:00:00:00
ip link set dev wlan1 address 08:02:11:00:00:01
iw wlan0 set type ibss
ip l set wlan0 up
iw wlan0 ibss join $(echo -n -e "\x10\x10\x10\x10\x10\x10") 2412 fixed-freq 50:50:50:50:50:50

iw wlan1 set type ibss
ip l set wlan1 up
iw wlan1 ibss join $(echo -n -e "\x10\x10\x10\x10\x10\x10") 2412 fixed-freq 50:50:50:50:50:50

until ip link show wlan0 | grep "state UP"; do sleep 1; done;
until ip link show wlan1 | grep "state UP"; do sleep 1; done;

iw wlan0 scan trigger;
iw wlan1 scan trigger;

echo "SYZKALLER SETUP FINISHED" > /dev/kmsg