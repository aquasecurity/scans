var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Storage Bucket Retention Policy',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensures bucket retention policy is set and locked to prevent deleting or updating of bucket objects or retention policy.',
    more_info: 'Configuring retention policy for bucket prevents accidental deletion as well as modification of bucket objects. This retention policy should also be locked to prevent policy deletion.',
    link: 'https://cloud.google.com/storage/docs/bucket-lock?_ga=2.221806616.-1645770163.1613190642',
    recommended_action: 'Modify bucket to configure retention policy and lock retention policy.',
    apis: ['buckets:list'],
    settings: {
        bucket_retention_days: {
            name: 'Bucket Retention Days',
            description: 'Return a passing result when bucket retention expiration date exceeds this number of days in the future',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '0'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            bucket_retention_days: parseInt(settings.bucket_retention_days || this.settings.bucket_retention_days.default)
        };

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

            var bucketFound = false;
            buckets.data.forEach(bucket => {
                if (bucket.name) {
                    let resource = helpers.createResourceName('b', bucket.name);
                    bucketFound = true;
                    if (bucket.retentionPolicy && bucket.retentionPolicy.retentionPeriod && bucket.retentionPolicy.effectiveTime) {
                        var retentionDays = Math.round(parseInt(bucket.retentionPolicy.retentionPeriod)/(24*60*60));
                        var now = new Date();
                        var then = new Date(bucket.retentionPolicy.effectiveTime);
                        var difference = helpers.daysBetween(then, now);
                        var effectiveDifference = retentionDays - difference;

                        if (effectiveDifference < 0) {
                            helpers.addResult(results, 2, 'Storage bucket retention has already expired', region, resource);
                        } else if (effectiveDifference < config.bucket_retention_days) {
                            helpers.addResult(results, 2, `Storage bucket retention will expire in ${effectiveDifference} days`, region, resource);
                        } else if (!bucket.retentionPolicy.isLocked) {
                            helpers.addResult(results, 2, 'Storage bucket retention policy is not locked', region, resource);
                        } else {
                            helpers.addResult(results, 0, `Storage bucket retention will expire in ${effectiveDifference} days`, region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2, 'Storage bucket does not have a retention policy', region, resource);
                    }
                }
            });

            if (!bucketFound) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}