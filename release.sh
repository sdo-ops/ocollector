#!/bin/sh

if [[ ! -e $1 ]] ; then
    echo 'which script you want to pack?'
    exit 1
fi

which fatpack 2>/dev/null 1>&2
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

final_script="release-$1"
cd ..
echo '#!/usr/bin/env perl' > $final_script
echo >> $final_script
cat release/$1.tmp >> $final_script
chmod +x $final_script
md5sum $final_script> $final_script.md5sum


exit 0
