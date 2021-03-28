#!/bin/bash

find /proc/ -mindepth 1 -maxdepth 1 -name '[1-9]*' | while read -r procpid; do
        stat -L -c '%20i %n' $procpid/ns/net
done 2>/dev/null