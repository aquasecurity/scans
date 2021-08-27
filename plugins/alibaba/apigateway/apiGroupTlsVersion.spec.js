var expect = require('chai').expect;
var apiGroupTlsVersion = require('./apiGroupTlsVersion')

const describeApiGroups = [
    {
        "GroupName": "test",
        "HttpsPolicy": "HTTPS2_TLS1_0",
        "GroupId": "da12e54692c2435ab4ef3b4d0274ea93",
        "RegionId": "cn-hangzhou",
        "InstanceType": "VPC_DEDICATED"
    },
    {
        "GroupName": "test",
        "HttpsPolicy": "HTTPS2_TLS1_2",
        "GroupId": "da12e54692c2435ab4ef3b4d0274ea93",
        "RegionId": "cn-hangzhou",
        "InstanceType": "VPC_DEDICATED"
    },
    {
        "GroupName": "test",
        "GroupId": "da12e54692c2435ab4ef3b4d0274ea93",
        "RegionId": "cn-hangzhou",
        "InstanceType": "VPC_DEDICATED"
    },
]
const createCache = (describeApiGroup) => {
    return {
        apigateway: {
            DescribeApiGroups: {
                'cn-hangzhou': {
                    data: describeApiGroup
                }
            }
        }
    }
}

const errorCache = () => {
    return {
        apigateway: {
            DescribeApiGroups: {
                'cn-hangzhou': {
                    err: 'Unable to describe API group'
                }
            }     
        }
    }
}

const nullCache = () => {
    return {
        apigateway: {
            DescribeApiGroups: {
                'cn-hangzhou': null
            }
        }
    }
}

describe('apiGroupTlsVersion', () => {
    describe('run', () => {       
         it('should PASS if API has latest TLS version', done => {
             const cache = createCache([describeApiGroups[1]]);
             apiGroupTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(0);
                 expect(results[0].message).to.include('API instance has latest TLS version');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
  
         it('should FAIL if API does not have latest TLS version', done => {
             const cache = createCache([describeApiGroups[0]]);
             apiGroupTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(2);
                 expect(results[0].message).to.include('API instance does not have latest TLS version');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });

         it('should FAIL if API response does not have HttpsPolicy', done => {
             const cache = createCache([describeApiGroups[2]]);
             apiGroupTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(2);
                 expect(results[0].message).to.include('API instance does not have latest TLS version');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should PASS if no api groups found', done => {
             const cache = createCache([]);
             apiGroupTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(0);
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });

         it('should UNKNOWN if unable to describe API groups', done => {
             const cache = errorCache();
             apiGroupTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(3);
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should not return anything if response not received', done => {
             const cache = nullCache();
             apiGroupTlsVersion.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(0);
                 done();
             });
         });
     })
 })
 