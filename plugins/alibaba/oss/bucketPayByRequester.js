var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Bucket Pay By Requester Enabled',
    category: 'OSS',
    domain: 'Storage',
    description: 'Ensure that OSS buckets have pay per requester feature enabled.',
    more_info: 'Enabling pay per requester for OSS buckets ensures that requesters pay the request and traffic fees that are incurred when the requesters access objects in the bucket.',
    recommended_action: 'Modify OSS buckets to enable pay per requester mode.',
    link: 'https://www.alibabacloud.com/help/doc-detail/91383.htm',
    apis: ['OSS:listBuckets', 'OSS:getBucketRequestPayment', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);

        var listBuckets = helpers.addSource(cache, source, ['oss', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);
        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, `Unable to query for OSS buckets: ${helpers.addError(listBuckets)}`, region);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No OSS buckets found', region);
            return callback(null, results, source);
        }

        async.each(listBuckets.data, (bucket, cb) => {
            if (!bucket.name) return cb();
            var getBucketRequestPayment = helpers.addSource(cache, source,
                ['oss', 'getBucketRequestPayment', region, bucket.name]);
            var bucketLocation = bucket.region || region;
            bucketLocation = bucketLocation.replace('oss-', '');

            var resource = helpers.createArn('oss', accountId, 'bucket', bucket.name, bucketLocation);

            if (!getBucketRequestPayment || getBucketRequestPayment.err || !getBucketRequestPayment.data) {
                helpers.addResult(results, 3,
                    `Unable to query OSS bucket info: ${helpers.addError(getBucketRequestPayment)}`, bucketLocation, resource);
                return cb();
            }

            if (getBucketRequestPayment.data.payer &&
                getBucketRequestPayment.data.payer.toLowerCase() === 'requester') {
                helpers.addResult(results, 0,
                    'Bucket has pay-by-requester feature enabled',
                    bucketLocation, resource);
            } else {
                helpers.addResult(results, 2,
                    'Bucket does not have pay-by-requester feature enabled',
                    bucketLocation, resource);
            }

            cb();
        }, function() {
            callback(null, results, source);
        });
    }
};
