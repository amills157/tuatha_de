#!/bin/bash

for i in $(cat docker_images.txt); do

echo $i

j=$(echo $i | awk -F ":" '{print $2}')

echo $j

./ogma.py -image $i -container $j -vis Both

done
