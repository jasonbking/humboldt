#!/usr/bin/bash

pipe="$1"
msg="$2"

echo
echo "--- RFD 77 zfs encryption unlock ---"
echo "$msg"
printf "Enter PIN: "
stty -echo
read pivpin
stty echo
echo

echo "$pivpin" >"$pipe"
exit 0
