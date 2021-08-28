var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Bucket Cross Region Replication Enabled',
    category: 'OSS',
    domain: 'Storage',
    description: 'Ensure that OSS buckets have cross region replication enabled.',
    more_info: 'Enabling Cross region replication for OSS buckets provides automatic and asynchronous replication of objects across buckets in different Object Storage Service (OSS) regions.',
    recommended_action: 'Modify OSS buckets to enable cross region replication.',
    link: 'https://www.alibabacloud.com/help/doc-detail/181408.htm?',
    apis: ['OSS:listBuckets', 'OSS:getBucketInfo', 'STS:GetCallerIdentity'],

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

            var getBucketInfo = helpers.addSource(cache, source,
                ['oss', 'getBucketInfo', region, bucket.name]);
            var bucketLocation = bucket.region || region;
            bucketLocation = bucketLocation.replace('oss-', '');

            var resource = helpers.createArn('oss', accountId, 'bucket', bucket.name, bucketLocation);

            if (!getBucketInfo || getBucketInfo.err || !getBucketInfo.data) {
                helpers.addResult(results, 3,
                    `Unable to query OSS bucket info: ${helpers.addError(getBucketInfo)}`, bucketLocation, resource);
                return cb();
            }

            if (getBucketInfo.data.CrossRegionReplication &&
                getBucketInfo.data.CrossRegionReplication.toLowerCase() == 'enabled') {
                helpers.addResult(results, 0,
                    'Bucket has cross region replication enabled',
                    bucketLocation, resource);
            } else {
                helpers.addResult(results, 2,
                    'Bucket does not have cross region replication enabled',
                    bucketLocation, resource);
            }

            cb();
        }, function() {
            callback(null, results, source);
        });
    }
};
