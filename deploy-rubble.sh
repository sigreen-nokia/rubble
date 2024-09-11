#!/bin/bash
echo "creating cloudformation stack"
# --template-url $S3bucketURL/config/rubble-root.json \
aws cloudformation create-stack \
  --capabilities CAPABILITY_IAM \
  --stack-name Rubble \
  --disable-rollback \
  --template-body file:///Users/sigreen/git/rubble/deployers/rubble-aws-deployer.json \
  --parameters \
ParameterKey=KeyName,ParameterValue="rubblekey" \
ParameterKey=VPCCIDR,ParameterValue="100.72.100.0/22" \
ParameterKey=SiteName,ParameterValue="rubble" \
ParameterKey=ConfigBackupNumberOfNodes,ParameterValue="1" \
ParameterKey=ConfigBackupLambdaScheduleStartExpression,ParameterValue="cron(30 20 * * ? *)" \
ParameterKey=ConfigBackupLambdaScheduleStopExpression,ParameterValue="cron(30 21 * * ? *)" \
ParameterKey=EmailServerURL,ParameterValue="smtp.gmail.com" \
ParameterKey=EmailUsername,ParameterValue="example@gmail.com" \
ParameterKey=EmailPassword,ParameterValue="xxxxxx" \
ParameterKey=EmailFromAddress,ParameterValue="example@gmail.com" \
ParameterKey=EmailToAddress,ParameterValue="example@gmail.com"
#the stacks are deploying lets check they come up and let the user know when its all ready
while [[ $(aws cloudformation describe-stacks --stack-name Rubble --query "Stacks[].StackStatus" --output text) != "CREATE_COMPLETE" ]];
do
     RESULT=$(aws cloudformation describe-stacks --stack-name Rubble --query "Stacks[].StackStatus" --output text)
     echo "$RESULT waiting for cloudformation stack to complete."
     sleep 60
done
echo "========"
echo "All Done"
echo "========"
aws cloudformation describe-stacks --stack-name Rubble --query "Stacks[0].Outputs[]" --output table
