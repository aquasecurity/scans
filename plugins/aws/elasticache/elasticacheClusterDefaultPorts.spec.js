const expect = require('chai').expect;
var elasticacheDefaultPort = require('./elasticacheClusterDefaultPorts');

const describeClusters = [
    {
        "CacheClusterId": "test-dev",
        "ConfigurationEndpoint": {
            "Address": "test-dev.1234.aaa.use1.cache.amazonaws.com",
            "Port": 11111
        },
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.r6g.large",
        "Engine": "memcached",
        "EngineVersion": "1.6.6",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1b",
        "CacheClusterCreateTime": "2021-08-23T17:26:45.535Z",
        "PreferredMaintenanceWindow": "mon:09:30-mon:10:30",
        "PendingModifiedValues": {},
        "CacheSecurityGroups": [],
        "CacheParameterGroup": {
            "CacheParameterGroupName": "default.memcached1.6",
            "ParameterApplyStatus": "in-sync",
            "CacheNodeIdsToReboot": []
        },
        "CacheSubnetGroupName": "test-dev-subnet-group",
        "AutoMinorVersionUpgrade": true,
        "SecurityGroups": [
            {
                "SecurityGroupId": "sg-1234",
                "Status": "active"
            }
        ],
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:978540712345:cluster:test-dev"
    },
    {
        "CacheClusterId": "test-dev",
        "ConfigurationEndpoint": {
            "Address": "test-dev.1234.aaa.use1.cache.amazonaws.com",
            "Port": 11211
        },
        "ClientDownloadLandingPage": "https://console.aws.amazon.com/elasticache/home#client-download:",
        "CacheNodeType": "cache.r6g.large",
        "Engine": "memcached",
        "EngineVersion": "1.6.6",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
        "PreferredAvailabilityZone": "us-east-1b",
        "CacheClusterCreateTime": "2021-08-23T17:26:45.535Z",
        "PreferredMaintenanceWindow": "mon:09:30-mon:10:30",
        "PendingModifiedValues": {},
        "CacheSecurityGroups": [],
        "CacheParameterGroup": {
            "CacheParameterGroupName": "default.memcached1.6",
            "ParameterApplyStatus": "in-sync",
            "CacheNodeIdsToReboot": []
        },
        "CacheSubnetGroupName": "test-dev-subnet-group",
        "AutoMinorVersionUpgrade": true,
        "SecurityGroups": [
            {
                "SecurityGroupId": "sg-1234",
                "Status": "active"
            }
        ],
        "AuthTokenEnabled": false,
        "TransitEncryptionEnabled": false,
        "AtRestEncryptionEnabled": false,
        "ARN": "arn:aws:elasticache:us-east-1:978540712345:cluster:test-dev"
    },
];


const createCache = (describeClusters) => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    data: describeClusters
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing clusters'
                    }
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': null
            }
        }
    };
};

describe('elasticacheClusterDefaultPorts', function () {
    describe('run', function () {

        it('should PASS if no cluster using default port', function (done) {
            const cache = createCache([describeClusters[0]]);
            elasticacheDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if no cluster using default port', function (done) {
            const cache = createCache([describeClusters[1]]);
            elasticacheDefaultPort.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no were clusters found', function (done) {
            const cache = createCache([]);
            elasticacheDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to describe cache clusters', function (done) {
            const cache = createErrorCache();
            elasticacheDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if describe cache clusters response not found', function (done) {
            const cache = createNullCache();
            elasticacheDefaultPort.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});