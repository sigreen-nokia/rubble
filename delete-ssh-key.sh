#!/bin/bash
aws ec2 delete-key-pair --key-name rubblekey
echo "${YELLOW}Deleted ec2 keypair named rubblekey ${RESTORE} "
aws ec2 describe-key-pairs 
