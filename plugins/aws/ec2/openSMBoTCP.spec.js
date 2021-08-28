var expect = require('chai').expect;
const openSMBoTCP = require('./openSMBoTCP');

const describeSecurityGroups = [
    {
        "Description": "default VPC security group",
        "GroupName": "default",
        "IpPermissions": [],
        "OwnerId": "111122223333",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "ElasticMapReduce-master",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-02e2c70cd463dca29",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-02e2c70cd463dca29",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Master group for Elastic MapReduce created on 2020-08-31T17:07:19.819Z",
        "GroupName": "ElasticMapReduce-master",
        "IpPermissions": [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "10.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-001639e564442dfec",
                        "UserId": "111122223333"
                    }
                ]
            },
            {
                "FromPort": 8443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "72.21.196.64/29"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 8443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "111122223333",
        "GroupId": "sg-001639e564442dfec",
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    }
];

const describeNetworkInterfaces = [
    {
        "AvailabilityZone": "us-east-1b",
        "Description": "RDSNetworkInterface",
        "Groups": [
          {
            "GroupName": "default",
            "GroupId": "sg-aa941691"
          },
          {
            "GroupName": "HTTP-Access",
            "GroupId": "sg-02e2c70cd463dca29"
          },
        ],
        "InterfaceType": "interface",
        "Ipv6Addresses": [],
        "MacAddress": "12:95:7b:ae:63:91",
        "NetworkInterfaceId": "eni-0681cbf0930452492",
        "OwnerId": "111122223333",
        "PrivateDnsName": "ip-172-31-93-52.ec2.internal",
        "PrivateIpAddress": "172.31.93.52",
        "PrivateIpAddresses": [
          {
            "Primary": true,
            "PrivateDnsName": "ip-172-31-93-52.ec2.internal",
            "PrivateIpAddress": "172.31.93.52"
          }
        ],
        "Ipv4Prefixes": [],
        "Ipv6Prefixes": [],
        "RequesterId": "amazon-rds",
        "RequesterManaged": true,
        "SourceDestCheck": true,
        "Status": "available",
        "SubnetId": "subnet-673a9a46",
        "TagSet": [],
        "VpcId": "vpc-99de2fe4"
    },
]

const listFunctions = [
    {
        "FunctionName": "test-lambda",
        "FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:test-lambda",
        "Runtime": "nodejs12.x",
        "Role": "arn:aws:iam::111122223333:role/lambda-role",
        "Handler": "index.handler",
        "CodeSize": 304,
        "Description": "",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2020-12-23T06:58:12.289+0000",
        "CodeSha256": "1LbkWTlxbeGxWCDcSB1hyIcv/HzJ6W3w6sibCRvjfAU=",
        "Version": "$LATEST",
        "VpcConfig": {
            "SubnetIds": [
                "subnet-6a8b635b",
                "subnet-c21b84cc"
            ],
            "SecurityGroupIds": [
                "sg-001639e564442dfec"
            ],
            "VpcId": "vpc-99de2fe4"
        },
        "Environment": {
            "Variables": {
                "password": "fastabc123",
                "key": "AQICA="
            }
        },
        "KMSKeyArn": null,
        "TracingConfig": {
            "Mode": "Active"
        },
        "MasterArn": null,
        "RevisionId": "3ed6bad6-8315-4aee-804a-ba9d332a8952",
        "State": null,
        "StateReason": null,
        "StateReasonCode": null,
        "LastUpdateStatus": null,
        "LastUpdateStatusReason": null,
        "LastUpdateStatusReasonCode": null,
        "PackageType": "Zip",
        "SigningProfileVersionArn": null,
        "SigningJobArn": null
    },
]

const createCache = (securityGroups, networkInterfaces, functions, securityGroupsErr, networkInterfacesErr, functionsErr) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    err: securityGroupsErr,
                    data: securityGroups
                }
            },
            describeNetworkInterfaces: {
                'us-east-1': {
                    err: networkInterfacesErr,
                    data: networkInterfaces
                }
            },
        },
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: functionsErr,
                    data: functions
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': null,
            },
            describeNetworkInterfaces: {
                'us-east-1': null,
            },
        },
        lambda: {
            listFunctions: {
                'us-east-1': null,
            },
        },
    };
};


describe('openSMBoTCP', function () {
    describe('run', function () {
        it('should PASS if no public open ports found', function (done) {
            const cache = createCache([describeSecurityGroups[0]], [describeNetworkInterfaces[0]], [listFunctions[0]]);
            openSMBoTCP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if security group has SMBoTCP TCP port open to public', function (done) {
            const cache = createCache([describeSecurityGroups[1]], [describeNetworkInterfaces[0]], [listFunctions[0]]);
            openSMBoTCP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if security group is unused', function (done) {
            const cache = createCache([describeSecurityGroups[2]], [describeNetworkInterfaces[0]], []);
            openSMBoTCP.run(cache, {ec2_skip_unused_groups: 'true'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            openSMBoTCP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNWON unable to describe security groups', function (done) {
            const cache = createCache(null, { message: 'Unable to describe security groups'});
            openSMBoTCP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe security groups response not found', function (done) {
            const cache = createNullCache();
            openSMBoTCP.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
