import boto3
import sys
import json
from datetime import datetime, timedelta, timezone
import uuid
from botocore.exceptions import ClientError
import base64
from io import StringIO
import csv
from envyaml import EnvYAML
from opensearchpy import OpenSearch, RequestsHttpConnection, AWSV4SignerAuth, helpers
import os

def make_opensearch_connection():
    # get environment variables from the lambda function    
    OPENSEARCH_HOST = os.environ['OPENSEARCH_HOST']
    OPENSEARCH_PORT = os.environ['OPENSEARCH_PORT']
    OPENSEARCH_REGION = os.environ['OPENSEARCH_REGION']

    credentials = boto3.Session().get_credentials()
    auth = AWSV4SignerAuth(credentials, OPENSEARCH_REGION)

    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=auth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )
    return client

def rules_check(event, context):
    allRegions = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-south-1', 'eu-west-3', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']
    # db = boto3.resource('dynamodb')
    # rulesCheckTable = db.Table('rules-check-cybergate-dev-table')

    credentials = boto3.Session().get_credentials()
    sts_client = boto3.client(
        'sts',
        aws_access_key_id=credentials.access_key,
        aws_secret_access_key=credentials.secret_key,
        aws_session_token=credentials.token,
        region_name='eu-west-1'
    )

    # cloudAccountArn = "arn:aws:iam::223495708457:role/CybergateAssumeRole-1904993"
    cloudAccountArn = "arn:aws:iam::715790284523:role/1904993-role"
    organisationId = "12345"
    ExternalId = "1904993"

    assume_response = sts_client.assume_role(
        RoleArn=cloudAccountArn,
        RoleSessionName='AWSCLI-Session',
        ExternalId=ExternalId
    )

    result = []
    for region in allRegions:
        ruleCheck_client = boto3.client(
            'apigateway',
            aws_access_key_id=assume_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=assume_response['Credentials']['SecretAccessKey'],
            aws_session_token=assume_response['Credentials']['SessionToken'],
            region_name=region
        )

        try:
            response1 = ruleCheck_client.get_rest_apis()
            for value in response1['items']:            
                response2 = ruleCheck_client.get_stages(restApiId=value['id'])
                for stageItem in response2['item']:
                    data = {
                        "rule_master_id":1,
                        "errorCode": "",
                        "organisationId": organisationId,
                        "resourceName": "stageName " + stageItem['stageName'],
                        "cloudAccountArn": cloudAccountArn,
                        "region": region,                            
                        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                    }
                    if stageItem['webAclArn'] == []:                        
                        data["rulesStatus"] = "Fail"
                    else:
                        data["rulesStatus"] = "Success"                 
                    result.append(data)
                    # rulesCheckTable.put_item(Item=data)
        except ClientError as e:
            print(e)
    if (len(result) > 0):
        try:
            opensearch_client = make_opensearch_connection()
            RULES_CHECK_INDEX = os.environ['RULES_CHECK_INDEX']
            resp = helpers.bulk(opensearch_client, result, index=RULES_CHECK_INDEX)
        except ClientError as e:
            print(e)

    # return {'data': json.dumps(result)}


# def rules_check():
#     response2 = []
#     roleCheck = {}
#     allRegions = ['us-east-2', 'us-east-1', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-3', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-south-1', 'eu-west-3', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-east-1', 'us-gov-west-1']
#     client = boto3.client(
#         'sts',
#         aws_access_key_id="ASIATICLB34UQTSMKSEY",
#         aws_secret_access_key="Ro5LEcQZ7k06GWyq/W1tHGZ5EF7ONj4yOMmC3mXp",
#         aws_session_token="IQoJb3JpZ2luX2VjEKX//////////wEaCWV1LXdlc3QtMSJGMEQCIEQZBY6l3Nd9PqoiwFjc1RBOr/kIk0GbuzRbdhTSCIQAAiAzDMoXz6KPSS2wCT8MsFzlaeBK65Ewzpg6w99QZTC9dSqdAwiu//////////8BEAAaDDIyMzQ5NTcwODQ1NyIMQ4t1g5lwY8YTPFdnKvECZiUeK9OKlFdl6Eit9WRpd5iJyG9c8VcwbO/uup7kGru5nVX19tNfTGUh9o/9oaGJ5cNILeB0027KIxbKKUUIVTxLZD5Rcm90gifLzyCM3+bemK6dvdN1H0VRtdY76vM4XECYbn52ODXGQbGiFlTXtrElp7jPNLcInwCTZKpf76epN7jVXuQaX+lRUGZRHinWBikOLrBq6JZt/6qlH0Es1ZSH6YigNo3b3TDOmwQJ9uUT9xyE6vlCqtJEAPOMKhbXhoqRZcLY3v+tLJvB3P+VKs+fJrhOb/XFihnMreeum2DJSxjPRDxYZyZEztI6BCPojoi/QwLnLpEKi9yfs/UeNyITC/pOQHgDdB/FqsKmh0b2JMFO/a022cmeGYbW+0TM5SQCJS1fgfOsBxbSOQJujEJvAYoPxsNrjOHdhJX49FYZlYxslRxLFSjW/w1dAvS6tbPpBr/ogX0SppnEY6AkE8J07wZBfOdMLAcK5y0DRaXOMJXCkYgGOqcB4D0qXPxLrKmWzxQBDrpnomaDdObCZDpJtPOQdh3W5fIjRbxGzLQF6ExZ06nhSLKwO6gFqMGxE3cLkLw0n7Psjduf/hqUjFc59bBIiupuQVKk8kBZ/puRFnsRJqILZOikDMyctYj4EfnSFWkIjV+ghVMq3cL6lJIJXEBeSwDYkGzzpe6ih7nPi2qmXl6VgJS3Pav96rLNx7/5ziEEp6+chIZiz20JBMk=",
#         region_name="us-east-1"
#     )

#     response = client.assume_role (
#         RoleArn='arn:aws:iam::715790284523:role/1904993-role',
#         RoleSessionName='AWSCLI-Session',
#         ExternalId='1904993'
#     )

#     # print(response)
                        

#     client = boto3.client(
#         'dynamodb',
#         aws_access_key_id="ASIATICLB34U6WPKK6A6",
#         aws_secret_access_key="UzKTe5yBJ9yw2xTyyn5aajzvbVfPhJPEku3GFhD/",
#         aws_session_token="IQoJb3JpZ2luX2VjECIaCWV1LXdlc3QtMSJIMEYCIQCyVE483jOCz2XYbsZE+xo2ih0j/9ft8jLhIHX0KH4Z7AIhAKG5jze0wkjrG3tfwAgYU1hM+Cg6450Rf4xVsMuR7PpHKp0DCOv//////////wEQABoMMjIzNDk1NzA4NDU3IgxZkz/zDu0QybDWbCcq8QINh0jkSWwmo7+EbZoZoonHsZ1Km1RagfZoHV53iMzZq3V1H3C89qPhlyKTLoxI5h7i4udPkkKWlNXJmHJxWc1FbnhWtdZuDys4HtVf4fA4lK6mNoNwwiV67U5E78kB8Hr2Ide4506qfUT29nSiL+wzzT/xZhJvTWQM/yRxTVN7b5KgKlENPG1R8NEtOvtZAH0K7I4Z08tTreE0fdTX65u9+TOiIoSw8HSKfLQ2rwrdntE4FVNHbEZDFJTBAs93+7FEI1UoflsQxj9bgZrHBWAC74Z5gQMdlK9fVixcajZyy974tgdVPvwDgcb1DkSM8GqrnSmb4pX1N5qcN5kqAWuXdfR11L82whL4wgUA9CXyC439VAfogXomfxsXrTsc2/Gr63Qg/4vNm80UADvtLaIOBjncRgQftg/o3ARtqpMzemHp4j3lJbZkqnLTBW6aPoS2VRhKvwkSiU7pp9Kx68qwErDgHGT+4nPo4W0/aqgO520w5oPMhgY6pQHdSsbIXt0e8OhcwzFVk20GpPn5YgL9/BmjXXQMySdCW1tjKxQo6UMBBLozrBCRYMtO17KGkV8QW6VGM18/mo5vU+WJd3wXsyCmGHXTPexjAXdi1R7Zu0jj+DdZbPgFeHmJ1gU7T1pzveJCSqDvqXw4MMT+vMlbIpg/dqb1qcjFl5S21YzV3UqnbWHaoQg9rrIdj9bHXHDDJpdI1haPTxXhTho0nDs=",
#         region_name="eu-west-1"
#     )
#     for region in allRegions:
#         _client = boto3.client(
#             'apigateway',
#             aws_access_key_id=response['Credentials']['AccessKeyId'],
#             aws_secret_access_key=response['Credentials']['SecretAccessKey'],
#             aws_session_token=response['Credentials']['SessionToken'],
#             region_name=region
#         )
#         response1 = _client.get_rest_apis(
#         )

#         print(response1)
#         for value in response1['items']:
#             response2 = _client.get_stages(
#                 restApiId=value['id']
#             )
#             for stageItem in response2['item']:
#                 if stageItem['webAclArn'] == []:
#                     print("failure")#"stageName" + stageItem['stageName']
#                 else:
#                     print("success")#"stageName" + stageItem['stageName']
#     return response1

# rules_check()

