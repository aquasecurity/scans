var expect = require('chai').expect;
const bucketCrossAccountAccess = require('./bucketCrossAccountAccess');

const listBuckets = [
    { 
        Name: 'test-bucket-130',
        CreationDate: '2020-09-10T09:11:40.000Z' 
    }
];

const getBucketPolicy = [
    {
        Policy: '{"Version": "2012-10-17", "Statement": [{ "Sid": "AllowGetObject","Effect": "Allow","Principal": {"AWS": ["arn:aws:iam::1111111111111:user/x","arn:aws:iam::1111111111111:user/y"]},"Action": "s3:GetObject","Resource": "arn:aws:s3:::ttest-bucket-130/*","Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-sdfasdfdsg546476"}}}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"PublicReadGetObject","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucketallusersacl/*"}]}'
    },
    {
        Policy: '{"Version":"2012-10-17","Statement":[]}'
    },
    {
        Policy: '{"Version":"2012-10-17"}'
    },
];

const createCache = (buckets, policy) => {
    var bucketName = (buckets && buckets.length) ? buckets[0].Name : null;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    [bucketName]: {
                        data: policy
                    },
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    err: {
                        message: 'error while listing s3 buckets'
                    },
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error while getting bucket policy'
                    },
                },
            },
        },
    };
};

const createPolicyErrorCache = (buckets) => {
    var bucketName = buckets[0].Name;
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: buckets
                }
            },
            getBucketPolicy: {
                'us-east-1': {
                    [bucketName]: {
                        err: {
                            code: 'NoSuchBucketPolicy'
                        }
                    }
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': null,
            },
            getBucketPolicy: {
                'us-east-1': null,
            },
        },
    };
};

describe('bucketCrossAccountAccess', function () {
    describe('run', function () {
        it('should PASS if S3 bucket policy contains policy to allow cross-account access to whitelisted accounts', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[0]);
            bucketCrossAccountAccess.run(cache, {
                "whitelisted_aws_account_principals": [
                    'arn:aws:iam::1111111111111:user/x',
                    'arn:aws:iam::1111111111111:user/y',
                ]
            }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if S3 bucket policy does not contain policy to allow cross-account access', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[1]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no S3 buckets to check', function (done) {
            const cache = createCache([]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if bucket policy does not contain any statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[2]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should Fail if no bucket policy found', function (done) {
            const cache = createPolicyErrorCache([listBuckets[0]]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if bucket policy is invalid JSON or does not contain valid statements', function (done) {
            const cache = createCache([listBuckets[0]], getBucketPolicy[3]);
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should UNKNOWN if unable to list s3 buckets', function (done) {
            const cache = createErrorCache();
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any result if s3 list buckets response is not found', function (done) {
            const cache = createNullCache();
            bucketCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
