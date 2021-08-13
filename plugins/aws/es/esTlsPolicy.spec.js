var assert = require('assert');
var expect = require('chai').expect;
var es = require('./esTlsPolicy');

const createCache = (listData, descData) => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    'mydomain': {
                        err: null,
                        data: descData
                    }
                }
            }
        }
    }
};

describe('esTlsPolicy', function () {
    describe('run', function () {
        it('should give passing result if no ES domains present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No ES domains found')
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            es.run(cache, {}, callback);
        })

        it('should give error result if ES domain is not configured to enforce HTTPS', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('ES domain is not configured to use TLS 1.2 policy')
                done()
            };

            const cache = createCache(
                [
                  {
                    DomainName: 'mydomain'
                  }
                ],
                {
                  DomainStatus: {
                    DomainName: 'mydomain',
                    ARN: 'arn:1234',
                    DomainEndpointOptions: {
                        TLSSecurityPolicy: 'Policy-Min-TLS-1-0-2019-07'
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give passing result if ES domain is configured to enforce HTTPS', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('ES domain is configured to use TLS 1.2 policy')
                done()
            };

            const cache = createCache(
                [
                  {
                    DomainName: 'mydomain'
                  }
                ],
                {
                  DomainStatus: {
                    DomainName: 'mydomain',
                    ARN: 'arn:1234',
                    DomainEndpointOptions: {
                        TLSSecurityPolicy: 'Policy-Min-TLS-1-2-2019-07'
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })
    })
})