var expect = require('chai').expect;
const unusedOpenPorts = require('./unusedOpenPorts'); // Asegúrate de que el nombre del archivo sea correcto

const securityGroups = [
    {
        "Description": "Allows SSH access to developer",
        "GroupName": "spec-test-sg",
        "IpPermissions": [{
            "FromPort": 22,
            "IpProtocol": "tcp",
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0"
                }
            ],
            "ToPort": 22,
            "UserIdGroupPairs": []
        }],
        "OwnerId": "12345654321",
        "GroupId": "sg-0b5f2771716acfee4",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4"
    },
    {
        "Description": "Open HTTP and HTTPS access",
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
                "ToPort": 80,
                "UserIdGroupPairs": []
            },
            {
                "FromPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0"
                    }
                ],
                "ToPort": 443,
                "UserIdGroupPairs": []
            }
        ],
        "OwnerId": "12345654321",
        "GroupId": "sg-0ff1642cae23c309a",
        "IpPermissionsEgress": [],
        "VpcId": "vpc-99de2fe4"
    }
];

const instances = [
    {
        "InstanceId": "i-1234567890abcdef0",
        "State": {
            "Name": "running"
        },
        "SecurityGroups": [
            {
                "GroupId": "sg-0ff1642cae23c309a"
            }
        ]
    }
];

const createCache = (securityGroups, instances) => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    data: securityGroups
                }
            },
            describeInstances: {
                'us-east-1': {
                    data: instances
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    }
                }
            },
            describeInstances: {
                'us-east-1': {
                    err: {
                        message: 'error describing instances'
                    }
                }
            }
        }
    };
};

describe('unusedOpenPorts', function () {
    describe('run', function () {
        it('should FAIL if there are unused open ports', function (done) {
            const cache = createCache([securityGroups[0]], instances);
            unusedOpenPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if all open ports are associated with running services', function (done) {
            const cache = createCache([securityGroups[1]], instances);
            unusedOpenPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there is an error describing security groups or instances', function (done) {
            const cache = createErrorCache();
            unusedOpenPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should PASS if no security groups or instances are found', function (done) {
            const cache = createCache([], []);
            unusedOpenPorts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});