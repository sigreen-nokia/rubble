#!/bin/bash
# Script to run 
#once we are ready this will run backup.py
#start up openvpn to deepfield
cd /home/ubuntu/*
pwd
#wait for the vpn to come up (its a vlabs only think)
sleep 60
#copy the backup over to deepfield
chmod 0600 ./deepfield-ssh-key
ssh -i ./deepfield-ssh-key -o StrictHostKeyChecking=no support@rubble-vlabs.deepfield.net ls
scp -i ./deepfield-ssh-key backup.py support@rubble-vlabs.deepfield.net:/home/support
scp -i ./deepfield-ssh-key backup.sh support@rubble-vlabs.deepfield.net:/home/support
echo "Running the backup"
ssh -i ./deepfield-ssh-key support@rubble-vlabs.deepfield.net 'chmod a+x /home/support/backup.sh'
ssh -i ./deepfield-ssh-key support@rubble-vlabs.deepfield.net '/bin/bash -lc "/home/support/backup.sh"' 
echo "backups on the remote host are"
ssh -i ./deepfield-ssh-key support@rubble-vlabs.deepfield.net 'ls -lrt /pipedream/cache/config_sync/'
#fetch the last backup on the cluster
export FILE=`ssh -i ./deepfield-ssh-key support@rubble-vlabs.deepfield.net 'ls -t /pipedream/cache/config_sync/ | head -n1'`
scp -i ./deepfield-ssh-key support@rubble-vlabs.deepfield.net:/pipedream/cache/config_sync/${FILE} . 
#copy the backup to the customers s3 bucket
aws s3 cp $FILE s3://deepfield-one-click-deployers
echo "========" 
echo "All Done" 
echo "========" 
