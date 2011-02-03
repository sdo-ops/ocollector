#!/bin/sh

if [[ ! -e $1 ]] ; then
    echo 'which script you want to pack?'
    exit 1
fi

which fatpack 2>/dev/null
if [[ $? != 0 ]] ; then
    echo 'install App::FatPacker first'
    exit 1
fi

rm -rf release
mkdir -p release/lib
cp $1 release
cd release || exit 1

fatpack trace $1
fatpack packlists-for `cat fatpacker.trace` >packlists
fatpack tree `cat packlists`
(fatpack file; cat $1) >$1.tmp

cd ..
echo '#!/usr/bin/env perl' > release-$1
echo >> release-$1
cat release/$1.tmp >> release-$1
chmod +x release-$1
md5sum release-$1 > release-$1.md5sum


exit 0
