var expect = require('chai').expect;
const openCustomPorts = require('./openCustomPorts');

const describeSecurityGroups = [
    {
        "Description": "Allows SSh access to developer",
        "GroupName": "spec-test-sg",
        "IpPermissions": [{
            "FromPort": 25,
            "IpProtocol": "tcp",
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0"
                }
            ],
            "Ipv6Ranges": [
                {
                    "CidrIpv6": "::/0"
                }
            ],
            "PrefixListIds": [],
            "ToPort": 160,
            "UserIdGroupPairs": []
        }],
        "OwnerId": "12345654321",
        "GroupId": "sg-aa941691",
        "IpPermissionsEgress": [
            {
                "FromPort": 25,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [
                    {
                        "CidrIpv6": "::/0"
                    }
                ],
                "PrefixListIds": [],
                "ToPort": 25,
                "UserIdGroupPairs": []
            }
        ],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "launch-wizard-1 created 2020-08-10T14:28:09.271+05:00",
        "GroupName": "launch-wizard-1",
        "IpPermissions": [
            {
                "FromPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 80,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "12345654321",
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
        "Description": "launch-wizard-1 created 2020-08-10T14:28:09.271+05:00",
        "GroupName": "launch-wizard-1",
        "IpPermissions": [
            {
                "FromPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 80,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "12345654321",
        "GroupId": "sg-02e2c70cd463dcafe",
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
]


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
                "sg-02e2c70cd463dca29"
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

const createCache = (groups, interfaces, functions) => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    data: groups
                },
            },
            describeNetworkInterfaces: {
                'us-east-1': {
                    data: interfaces
                },
            },
        },
        lambda: {
            listFunctions: {
                'us-east-1': {
                    data: functions
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2:{
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    },
                },
            },
            describeNetworkInterfaces: {
                'us-east-1': {
                    err: {
                        message: 'error describing network interfaces'
                    },
                },
            }
        },
        lambda: {
            listFunctions: {
                'us-east-1': {
                    err: {
                        message: 'error listing lambda functions'
                    },
                },
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
            }
        }
    };
};

describe('openCustomPorts', function () {
    describe('run', function () {
        it('should FAIL if security group has open ports', function (done) {
            const cache = createCache([describeSecurityGroups[0]], [describeNetworkInterfaces[0]], [listFunctions[0]]);
            openCustomPorts.run(cache, { restricted_open_ports: 'tcp:0-500,tcp:33-39,tcp:55' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if security group does not have open ports', function (done) {
            const cache = createCache([describeSecurityGroups[1]], [describeNetworkInterfaces[0]], [listFunctions[0]]);
            openCustomPorts.run(cache, { restricted_open_ports: 'tcp:25,tcp:26' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if security group is unused', function (done) {
            const cache = createCache([describeSecurityGroups[2]], [describeNetworkInterfaces[0]], []);
            openCustomPorts.run(cache, {ec2_skip_unused_groups: 'true', restricted_open_ports: 'tcp:25,tcp:26'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no security groups found', function (done) {
            const cache = createCache([]);
            openCustomPorts.run(cache, { restricted_open_ports: 'tcp:22' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe security groups', function (done) {
            const cache = createErrorCache();
            openCustomPorts.run(cache, { restricted_open_ports: 'tcp:22' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if describe security groups response not found', function (done) {
            const cache = createNullCache();
            openCustomPorts.run(cache, { restricted_open_ports: 'tcp:22' }, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});