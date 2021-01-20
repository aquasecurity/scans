// Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html

var regions = [
    'cn-north-1',
    'cn-northwest-1'
];

module.exports = {
    default: ['cn-north-1'],
    all: regions,
    optin: [],
    acm: [],
    apigateway: regions,
    athena: [],
    cloudfront: [],
    efs: [],
    autoscaling: regions,
    iam: ['cn-north-1'],
    route53: [],
    route53domains: [],
    s3: regions,
    s3control: regions,
    cloudtrail: regions,
    cloudwatchlogs: regions,
    cloudformation: regions,
    comprehend: [],
    configservice: regions,
    dlm: regions,
    dms: regions,
    dax: ['cn-northwest-1'],
    dynamodb: regions,
    ec2: regions,
    ecr: regions,
    eks: [],
    elasticbeanstalk: regions,
    elastictranscoder: [],
    elb: regions,
    elbv2: regions,
    emr: regions,
    es: regions,
    kinesis: [],
    firehose: regions,
    kms: regions,
    vpc: regions,
    flowlogs: regions,
    rds: regions,
    redshift: regions,
    cloudwatch: regions,
    ecs: regions,
    sagemaker: [],
    ses: [],
    servicequotas: [],
    shield: [],
    sns: regions,
    sqs: regions,
    ssm: regions,
    // SSE via KMS is only supported in some regions
    // even though SQS is supported in all regions.
    sqs_encrypted: regions,
    sts: regions,
    support: [],
    transfer: [],
    lambda: regions,
    directconnect: regions,
    directoryservice: [],
    organizations: ['cn-north-1'],
    guardduty: [],
    wafregional: [],
    wafv2: [],
    workspaces: ['cn-northwest-1'],
    xray: regions,
    resourcegroupstaggingapi: regions
};
