var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Bucket Lifecycle Configuration',
    category: 'S3',
    domain: 'Storage',
    description: 'Ensures that S3 buckets have lifecycle configuration enabled to automatically transition S3 bucket objects.',
    more_info: 'S3 bucket should have lifecycle configuration enabled to automatically downgrade the storage class for your objects.',
    recommended_action: 'Update S3 bucket and create lifecycle rule configuration',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-set-lifecycle-configuration-intro.html',
    apis: ['S3:listBuckets', 'S3:getBucketLifecycleConfiguration', 'S3:getBucketLocation'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                `Unable to query for S3 buckets: ${helpers.addError(listBuckets)}`);
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets found');
            return callback(null, results, source);
        }

        async.each(listBuckets.data, function(bucket, cb){
            if (!bucket.Name) return cb();

            var resource = `arn:aws:s3:::${bucket.Name}`;
            var bucketLocation = helpers.getS3BucketLocation(cache, region, bucket.Name);

            var getBucketLifecycleConfiguration = helpers.addSource(cache, source,
                ['s3', 'getBucketLifecycleConfiguration', region, bucket.Name]);

            if (getBucketLifecycleConfiguration && getBucketLifecycleConfiguration.err &&
                getBucketLifecycleConfiguration.err.code && getBucketLifecycleConfiguration.err.code == 'NoSuchLifecycleConfiguration') {
                helpers.addResult(results, 2,
                    `S3 bucket ${bucket.Name} does not have lifecycle configuration enabled`,
                    bucketLocation, resource);
            } else if (!getBucketLifecycleConfiguration || getBucketLifecycleConfiguration.err || !getBucketLifecycleConfiguration.data) {
                helpers.addResult(results, 3,
                    `Unable to query for S3 bucket lifecycle configuration: ${helpers.addError(getBucketLifecycleConfiguration)}`,
                    bucketLocation, resource);
            } else if (getBucketLifecycleConfiguration.data.Rules &&
                getBucketLifecycleConfiguration.data.Rules.length) {
                var ruleExists = getBucketLifecycleConfiguration.data.Rules.find(rule => rule.Status && rule.Status.toUpperCase() === 'ENABLED');

                if (ruleExists) {
                    helpers.addResult(results, 0,
                        `S3 bucket ${bucket.Name} has lifecycle configuration enabled`,
                        bucketLocation, resource);
                } else {
                    helpers.addResult(results, 2,
                        `S3 bucket ${bucket.Name} does not have lifecycle configuration enabled`,
                        bucketLocation, resource);
                }
            } else {
                helpers.addResult(results, 2,
                    `S3 bucket ${bucket.Name} does not have lifecycle configuration enabled`,
                    bucketLocation, resource);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};