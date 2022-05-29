#!/bin/bash

for i in $(cat image_list.txt); do

echo $i

j=$(echo $i | awk -F "_" '{print $1}')

echo $j

./ogma.py -image $i -vis single -refresh true -container $j -nofix show

done
