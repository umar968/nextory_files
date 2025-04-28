import boto3

# Source Account Credentials
source_s3 = boto3.client('s3',
                         aws_access_key_id="519FJZYVBS5VM0EBLGPN",
                         aws_secret_access_key="TeeRHkHzmnyqetCnJP6qJyyzXKHSX0gWvzuTtkF0",
                         endpoint_url="https://s3.eu-central-2.wasabisys.com"
                         )

# Destination Account Credentials

destination_s3 = boto3.client('s3',
                              aws_access_key_id="AKIAVVZPCVIRNAZIRFOD",
                              aws_secret_access_key="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",
                              endpoint_url="https://s3.us-east-1.amazonaws.com"
                              )


def transfer_s3_objects(source_bucket, destination_bucket, source_prefix, destination_prefix):
    paginator = source_s3.get_paginator('list_objects_v2')

    for page in paginator.paginate(Bucket=source_bucket, Prefix=source_prefix):
        print(page['Contents'])
        if 'Contents' in page:
            for obj in page['Contents']:
                source_key = obj['Key']

                if source_key != "ebooks/":
                    try:
                        obj_response = source_s3.get_object(Bucket=source_bucket, Key=source_key)
                        data = obj_response['Body'].read()
                        destination_s3.put_object(Bucket=destination_bucket, Body=data,
                                                  Key=destination_prefix + source_key)
                        source_s3.delete_object(Bucket=source_bucket, Key=source_key)
                        print(f"Moved {obj['Key']}")

                    except Exception as e:
                        print('Error:', e)


if __name__ == "__main__":
    source_bucket_name = "nextory"
    source_prefix = "ebook"
    destination_bucket_name = "digecool"
    destination_prefix = "storage/app/ecommerce/nextory/"

    transfer_s3_objects(source_bucket_name, destination_bucket_name, source_prefix, destination_prefix)
