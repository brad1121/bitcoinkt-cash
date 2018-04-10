#!/bin/bash
OLDNAME="org.bitcoinj"
NEWNAME="cash.bitcoinj"
NEWDIR="cash"
TFILE="./out.tmp.$$"

echo "Renaming to cash.bitcoinj"
cd ../

FOLDERS=0
	for d in $(find ./ -path "*java/org/bitcoinj")
	do
		RESULT="${d/org/$NEWDIR}"
		RESULT="${RESULT%/bitcoinj*}"
		#echo $RESULT
		mv $d $RESULT
		let FOLDERS++
	done

FILES=0
for f in $(find . -type f)
do
    if [ -f $f -a -r $f ]; then
	#echo "checking $f"
      if grep -q "package $OLDNAME" $f; then
		#echo "found $OLDNAME"
            	sed  -i "s/$OLDNAME/$NEWNAME/g" $f
		let FILES++
      fi
	#clear
    else
        echo "Can't read $f"
    fi
done

echo "Complete: Renamed $FOLDERS folders and modified $FILES files"



