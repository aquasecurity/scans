var expect = require('chai').expect;
const albSecurityGroup = require('./albSecurityGroup');

const loadBalancers = [
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-lb-43/8e680c7bace394a7",
        "DNSName": "test-lb-43-148538634.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2020-08-30T22:55:21.030Z",
        "LoadBalancerName": "test-lb-43",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "application",
        "SecurityGroups": [
            "sg-06cccc47e5b3e1ee9"
        ],
        "IpAddressType": "ipv4"
    },
    {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test-lb-43/8e680c7bace394a8",
        "DNSName": "test-lb-43-148538634.us-east-1.elb.amazonaws.com",
        "CanonicalHostedZoneId": "Z35SXDOTRQ7X7K",
        "CreatedTime": "2020-08-30T22:55:21.030Z",
        "LoadBalancerName": "test-lb-43",
        "Scheme": "internet-facing",
        "VpcId": "vpc-99de2fe4",
        "State": {
            "Code": "active"
        },
        "Type": "application",
        "SecurityGroups": [],
        "IpAddressType": "ipv4"
    }
];


const createCache = (elbv2) => {
    return {
        elbv2:{
            describeLoadBalancers: {
                'us-east-1': {
                    data: elbv2
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': {
                    err: {
                        message: 'error describing load balancers'
                    },
                },
            },
        }
    };
};

const createNullCache = () => {
    return {
        elbv2: {
            describeLoadBalancers: {
                'us-east-1': null,
            },
        },
    };
};

describe('albSecurityGroup', function () {
    describe('run', function () {
        it('should PASS if load balancer has security groups associated', function (done) {
            const cache = createCache([loadBalancers[0]]);
            albSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).include('Application Load Balancer has security group associated');
                done();
            });
        });
        
        it('should FAIL if load balancer does not have security groups associated', function (done) {
            const cache = createCache([loadBalancers[1]]);
            albSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).include('Application Load Balancer does not have security group associated');
                done();
            });
        });

        it('should UNKNOWN if error while describing load balancers', function (done) {
            const cache = createErrorCache();
            albSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).include('Unable to query for load balancers:');
                done();
            });
        });
        
        it('should PASS if no load balancer found', function (done) {
            const cache = createCache([]);
            albSecurityGroup.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).include('No load balancers found');
                done();
            });
        });
        
        
    });
});
