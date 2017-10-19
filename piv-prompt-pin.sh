#!/usr/bin/bash

guid="$1"
reader="$2"

echo
echo "A PIN is required to unlock hardware token keys that protect"
echo "encrypted data on this system."
echo
echo "PIV token GUID: ${guid}"
echo "Attached to: ${reader}"
echo

attempt_unlock() {
	pivtool -g "$guid" set-system
	case $? in
	0)
		exit 0
		;;
	4)
		attempt_unlock
		;;
	*)
		echo
		exit 1
		;;
	esac
}
attempt_unlock
exit 0
