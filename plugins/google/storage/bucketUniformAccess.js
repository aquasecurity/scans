var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Uniform Level Access',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensures that uniform level access is enabled on storage buckets.',
    more_info: 'Uniform level access for buckets can be used for managing access in a simple way. It enables us to use other security features like IAM conditions.',
    link: 'https://cloud.google.com/storage/docs/uniform-bucket-level-access#should-you-use',
    recommended_action: 'Make sure that storage buckets have uniform level access enabled',
    apis: ['buckets:list'],
  
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.buckets, function(region, rcb){
            let buckets = helpers.addSource(
                cache, source, ['buckets', 'list', region]);

            if (!buckets) return rcb();

            if (buckets.err || !buckets.data) {
                helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region);
                return rcb();
            }

            if (!buckets.data.length) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }

            var bucketFound = false;
            buckets.data.forEach(bucket => {
                if (bucket.name) {
                    let resource = helpers.createResourceName('b', bucket.name);
                    bucketFound = true;
                    if (bucket.iamConfiguration &&
                        bucket.iamConfiguration.uniformBucketLevelAccess && 
                        bucket.iamConfiguration.uniformBucketLevelAccess.enabled) {
                        helpers.addResult(results, 0, 'Bucket has uniform bucket level access enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2, 'Bucket does not have uniform bucket level access enabled', region, resource);
                    }
                }

                if (!bucketFound) {
                    helpers.addResult(results, 0, 'No storage buckets found', region);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}