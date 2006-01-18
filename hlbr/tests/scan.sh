#!/bin/bash

a=`grep HLBR *|cut -d: -f1|sort|uniq`

for i in `echo $a`
do
sed 's/HLBR/HLBR/g' $i > $i.2
mv $i.2 $i
done

