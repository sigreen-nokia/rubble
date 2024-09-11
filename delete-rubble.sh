REGION="eu-west-3"
#fixes a problem with cloudformation deletes hanging when lambda custom resources are present
for LAMBDA in $(aws lambda list-functions --query "Functions[].FunctionName" --o table | grep LamdbaS3CopyStack | tr -d ' ' | tr -d '|');
do
    echo "deleting lamdba function $LAMBDA"
    aws lambda delete-function --function-name $LAMBDA 
done
echo "deleting the cloudformation stack"
aws cloudformation delete-stack --stack-name Rubble 
echo "If you do not want to wait for the delete to finish you can hit cntrl-c"
aws cloudformation wait stack-delete-complete --stack-name Rubble 
echo "All Done"
