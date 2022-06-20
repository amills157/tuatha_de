#!/bin/bash

for i in $(cat docker_images.txt); do

echo $i

j=$(echo $i | awk -F ":" '{print $2}')

echo $j

./ogma.py -image $i -vis single -container $j -update yes

done
