var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account Managed Keys',
    category: 'IAM',
    domain: 'Identity and Access Management',
    description: 'Ensures that service account keys are being managed by Google.',
    more_info: 'Service account keys should be managed by Google to ensure that they are as secure as possible, including key rotations and restrictions to the accessibility of the keys.',
    link: 'https://cloud.google.com/iam/docs/creating-managing-service-account-keys',
    recommended_action: 'Ensure all user service account keys are being managed by Google.',
    apis: ['serviceAccounts:list','keys:list'],

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
            keys.data.forEach(key => {
                if (key.keyType &&
                    key.keyType === 'USER_MANAGED') {
                    var accountEmail = key.name.split('/')[3];
                    accountEmail = accountEmail.split('.');
                    if (accountEmail[1] === 'iam' &&
                        accountEmail[2] === 'gserviceaccount') {
                        helpers.addResult(results, 2,
                            'The user service account key is not being managed by Google', region, key.name);
                    } 
                } else {
                    helpers.addResult(results, 0, 'The user service account key is being managed by Google', region, key.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}