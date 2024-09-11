REGION="eu-west-3"
echo "deleting any left over tmp-rubble buckets in my region"
for BUCKET in $(aws s3api list-buckets | jq '.Buckets[].Name' -r | grep tmp-rubble-);
do
    BUCKET_REGION=$(aws s3api get-bucket-location --bucket $BUCKET | jq '.LocationConstraint' -r)
    echo "checking bucket $BUCKET in region $BUCKET_REGION"
    if [ "$BUCKET_REGION" = "$REGION" ];
    then
        echo "deleting bucket $bucket"
        aws s3 rb s3://$BUCKET --force
    fi
done
echo "deleting any left over rubble-s3stack- buckets in my region"
for BUCKET in $(aws s3api list-buckets | jq '.Buckets[].Name' -r | grep rubble-s3stack-);
do
    BUCKET_REGION=$(aws s3api get-bucket-location --bucket $BUCKET | jq '.LocationConstraint' -r)
    echo "checking bucket $BUCKET in region $BUCKET_REGION"
    if [ "$BUCKET_REGION" = "$REGION" ];
    then
        echo "deleting bucket $bucket"
        aws s3 rb s3://$BUCKET --force
    fi
done
echo "deleting the rubble s3 bucket"
aws s3 rm s3://$(aws cloudformation describe-stacks --stack-name Rubble --query "Stacks[0].Outputs[]" --output text | grep S3BucketID | awk 'NF{ print $NF }') --recursive
echo "All Done"
aws s3 ls
