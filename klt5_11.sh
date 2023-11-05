#!/bin/bash
if test $# -ge 1;then
ker_mv=$(echo $1|sed 's/\..*$//g')
if test $ker_mv -lt 5;then
	echo lt
elif test $ker_mv -gt 5;then
	echo eg
elif test $(echo $1|sed 's/^[^.]*\.//g'|sed 's/\..*$//g') -lt 11;then
	echo lt
else
	echo eg
fi
else 
	echo eg
fi
