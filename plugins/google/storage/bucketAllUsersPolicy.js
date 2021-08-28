var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Storage Bucket All Users Policy',
    category: 'Storage',
    domain: 'Storage',
    description: 'Ensures Storage bucket policies do not allow global write, delete, or read permissions',
    more_info: 'Storage buckets can be configured to allow the global principal to access the bucket via the bucket policy. This policy should be restricted only to known users or accounts.',
    link: 'https://cloud.google.com/storage/docs/access-control/iam',
    recommended_action: 'Ensure that each storage bucket is configured so that no member is set to allUsers or allAuthenticatedUsers.',
    apis: ['buckets:list','buckets:getIamPolicy'],

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

            let bucketPolicyPolicies = helpers.addSource(cache, source,
                ['buckets', 'getIamPolicy', region]);

            if (!bucketPolicyPolicies) return rcb();

            if (bucketPolicyPolicies.err || !bucketPolicyPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query bucket policies: ' + helpers.addError(bucketPolicyPolicies), region, null, null, bucketPolicyPolicies.err);
                return rcb();
            }

            if (!bucketPolicyPolicies.data.length) {
                helpers.addResult(results, 0, 'No storage buckets found', region);
                return rcb();
            }
            var badBuckets = [];
            bucketPolicyPolicies.data.forEach(bucketPolicy => {
                if (bucketPolicy.bindings &&
                    bucketPolicy.bindings.length) {
                    bucketPolicy.bindings.forEach(binding => {
                       if (binding.members &&
                           binding.members.length) {
                           binding.members.forEach(member => {
                               if (member === "allUsers" ||
                                   member === "allAuthenticatedUsers") {
                                    var resourceIdArr = bucketPolicy.resourceId.split('/');
                                    var bucketName = resourceIdArr[resourceIdArr.length - 1];
                                    if (badBuckets.indexOf(bucketName) === -1) {
                                        badBuckets.push(bucketName);
                                    }
                               }
                           })
                       }
                    })
                }
            });

            if (badBuckets.length) {
                badBuckets.forEach(bucket => {
                    let resource = helpers.createResourceName('b', bucket);
                    helpers.addResult(results, 2,
                        'Bucket has anonymous or public access', region, resource);
                });
            } else {
                helpers.addResult(results, 0, 'No buckets have anonymous or public access.', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}