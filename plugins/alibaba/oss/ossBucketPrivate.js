var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'OSS Bucket Private',
    category: 'OSS',
    domain: 'Storage',
    description: 'Ensure that OSS bucket is not publicly accessible.',
    more_info: 'When you allow public-access on an OSS bucket, all Internet users can access the objects in the bucket ' +
        'and write data to the bucket. This may cause unexpected access to the data in your bucket, and cause an increase in your fees. ' +
        'If a user uploads prohibited data or information, it may affect your legitimate interests and rights. ',
    recommended_action: 'Modify bucket ACL to restrict access to be private.',
    link: 'https://www.alibabacloud.com/help/doc-detail/31843.htm',
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

            if (getBucketInfo.data.AccessControlList &&
                getBucketInfo.data.AccessControlList.Grant &&
                getBucketInfo.data.AccessControlList.Grant == 'private') {
                helpers.addResult(results, 0,
                    `Bucket ACL allows ${getBucketInfo.data.AccessControlList.Grant} access`,
                    bucketLocation, resource);
            } else {
                helpers.addResult(results, 2,
                    `Bucket ACL allows ${getBucketInfo.data.AccessControlList.Grant} access`,
                    bucketLocation, resource);
            }

            cb();
        }, function() {
            callback(null, results, source);
        });
    }
};
