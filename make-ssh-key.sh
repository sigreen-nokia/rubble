#!/bin/bash
aws ec2 create-key-pair --key-name rubblekey --output text > ~/.ssh/rubblekey.pub
echo "${YELLOW}Created an ec2 keypair for you  named rubblekey ${RESTORE} "
aws ec2 describe-key-pairs 
