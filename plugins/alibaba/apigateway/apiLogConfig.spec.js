var expect = require('chai').expect;
var apiLogConfig = require('./apiLogConfig')

const describeLogConfig = {
    "SlsLogStore": "api-logstore",
    "SlsProject": "api-log",
    "LogType": "PROVIDER",
    "RegionId": "cn-hangzhou"
}

const describeApis = {
    "GroupName": "test_group",
    "CreatedTime": "2021-08-24T05:47:32Z",
    "ModifiedTime": "2021-08-24T05:47:32Z",
    "ApiName": "test_api",
    "Visibility": "PRIVATE",
    "RegionId": "cn-hangzhou",
    "ApiId": "69567aca1ff14efe8b864fb1a6f58f32",
    "GroupId": "db81d7d3fd794d3db5a4642afb408fa7"
}


const createCache = (describeApi, logConfig) => {
    return {
        apigateway: {
            DescribeLogConfig: {
                'cn-hangzhou': {
                    data: logConfig
                }
            },
            DescribeApis: {
                'cn-hangzhou': {
                    data: describeApi
                }
            }
        }
    }
}

const errorCache = () => {
    return {
        apigateway: {
            DescribeLogConfig: {
                'cn-hangzhou': {
                    err: 'Unable to describe log config',
                }
            },
            DescribeApis: {
                'cn-hangzhou': {
                    err: 'Unable to describe APIs',
                }
            }
        }
    }
}

const nullCache = () => {
    return {
        apigateway: {
            DescribeLogConfig: {
                'cn-hangzhou': null
            },
            DescribeApis: {
                'cn-hangzhou': null
            }
        }
    }
}

describe('apiLogConfig', () => {
    describe('run', () => {       
         it('should PASS if API has log service configured', done => {
             const cache = createCache([describeApis],[describeLogConfig]);
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(0);
                 expect(results[0].message).to.include('APIs are configured to publish logs to Log Service');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
  
         it('should PASS if no API found', done => {
             const cache = createCache([],[describeLogConfig]);
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(0);
                 expect(results[0].message).to.include('No APIs found');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
  
         it('should FAIL if API does not have log service configured', done => {
             const cache = createCache([describeApis], [{}]);
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(2);
                 expect(results[0].message).to.include('APIs are not configured to publish logs to Log Service');
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should UNKNOWN if unable to describe log config', done => {
             const cache = errorCache();
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(1);
                 expect(results[0].status).to.equal(3);
                 expect(results[0].region).to.equal('cn-hangzhou');
                 done();
             });
         });
 
         it('should not return anything if response not received', done => {
             const cache = nullCache();
             apiLogConfig.run(cache, {}, (err, results) => {
                 expect(results.length).to.equal(0);
                 done();
             });
         });
     })
 })
 