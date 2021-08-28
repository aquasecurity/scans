var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Bucket Versioning',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensures object versioning is enabled on storage buckets',
    more_info: 'Object versioning can help protect against the overwriting of objects or data loss in the event of a compromise.',
    link: 'https://cloud.google.com/storage/docs/using-object-versioning',
    recommended_action: 'Bucket Versioning can only be enabled by using the Command Line Interface, use this command to enable Versioning: gsutil versioning set on gs://[BUCKET_NAME]',
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
                helpers.addResult(results, 3, 'Unable to query storage buckets: ' + helpers.addError(buckets), region, null, null, buckets.err);
                return rcb();
            }

            if (!helpers.hasBuckets(buckets.data)) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }

            buckets.data.forEach(bucket => {
                if (bucket.name) {
                    let resource = helpers.createResourceName('b', bucket.name);
                    if (bucket.versioning &&
                        bucket.versioning.enabled) {
                        helpers.addResult(results, 0, 'Bucket versioning Enabled', region, resource);
                    } else if ((bucket.versioning &&
                        !bucket.versioning.enabled) ||
                        !bucket.versioning){
                        helpers.addResult(results, 2, 'Bucket versioning not Enabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0, 'No storage buckets found', region);
                    return
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}