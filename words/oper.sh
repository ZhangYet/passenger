#!/usr/bin/env bash

while read -r line;
do
    ../record-word.sh $line
    sleep 1
done < words

   
