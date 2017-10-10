#!/usr/bin/bash

pipe="$1"
msg="$2"

echo
echo "A PIN is required to unlock hardware token keys that protect"
echo "encrypted ZFS datasets on this system."
echo "$msg"
pivpin=""
while [[ ${#pivpin} -lt 6 ]]; do
	printf "Enter PIN: "
	stty -echo
	read pivpin
	stty echo
	echo
done

echo "$pivpin" >"$pipe"
exit 0
