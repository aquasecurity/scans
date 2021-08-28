var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account Key Rotation',
    category: 'IAM',
    domain: 'Identity and Access Management',
    description: 'Ensures that service account keys are rotated within 90 days of creation.',
    more_info: 'Service account keys should be rotated so older keys that that might have been lost or compromised cannot be used to access Google services.',
    link: 'https://cloud.google.com/iam/docs/creating-managing-service-account-keys',
    recommended_action: 'Rotate service account keys that have not been rotated in over 90 days.',
    apis: ['serviceAccounts:list','keys:list'],
    compliance: {
        hipaa: 'Rotating access keys helps to ensure that those keys have not been ' +
              'compromised. HIPAA requires strict controls around authentication of ' +
              'users or systems accessing HIPAA-compliant environments.',
        pci: 'PCI requires that all user credentials are rotated every 90 days. While ' +
             'IAM roles handle rotation automatically, access keys need to be manually ' +
             'rotated.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.keys, function(region, rcb){
            let keys = helpers.addSource(cache, source,
                ['keys', 'list', region]);

            if (!keys) return rcb();

            if (keys.err || !keys.data) {
                helpers.addResult(results, 3, 'Unable to query service account keys, check permissions.', region, null, null, keys.err);
                return rcb();
            };

            if (!keys.data.length) {
                helpers.addResult(results, 0, 'No service account keys found', region);
                return rcb();
            }
            var keysNotRotated = [];
            keys.data.forEach(key => {
                if (key.keyType &&
                    key.keyType === 'USER_MANAGED') {
                    var ninety_days = 90*24*60*60*1000;
                    var validAfterTime = key.validAfterTime.split("T")[0];

                    var timeFromCreation = new Date().getTime() - new Date(validAfterTime).getTime();
                    timeFromCreation /= ninety_days;

                    if (timeFromCreation > 1) {
                        helpers.addResult(results, 2,
                            'The service account key has not been rotated in over 90 days', region, key.name);
                    } else {
                        helpers.addResult(results, 0, 'The service account key has been rotated within 90 days', region, key.name);
                    }
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}