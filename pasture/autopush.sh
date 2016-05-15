#!/bin/sh
#
# autopush.sh
# Automatically push a file in this repo
# By J. Stuart McMurray
# Created 20160119
# Last Modified 20160119

set -e

if [[ -z $1 ]]; then
        /bin/echo "Usage: $0 file" >2
        exit 1
fi

cd $(/usr/bin/dirname $0)

/usr/local/bin/git commit --quiet --message "Autopush" $1
/usr/local/bin/git push --quiet 
