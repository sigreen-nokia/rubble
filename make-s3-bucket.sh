#!/bin/bash
# vars to build up the temp s3 folder
UUID=`python3  -c 'import uuid; print (uuid.uuid4())'`
TempS3bucket="tmp-rubble-"${UUID}
tempS3bucketURL="https://$TempS3bucket.s3-eu-west-3.amazonaws.com"
aws s3 mb s3://${TempS3bucket}
#echo "${YELLOW}I have just create s3 bucket s3://${TempS3bucket} for you{RESTORE} "
echo "========"
echo "All Done"
echo "========"
aws s3 ls 
