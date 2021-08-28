var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Deletion Protection Enabled',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures deletion protection is enabled for RDS database instances.',
    more_info: 'Deletion protection prevents Amazon RDS instances from being deleted accidentally by any user.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/',
    recommended_action: 'Modify the RDS instances to enable deletion protection.',
    apis: ['RDS:describeDBInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            describeDBInstances.data.forEach(instance => {
                if (!instance.DBInstanceArn) return;

                if (instance.DeletionProtection) {
                    helpers.addResult(results, 0,
                        'RDS instance has deletion protection enabled', region, instance.DBInstanceArn);
                } else {
                    helpers.addResult(results, 2,
                        'RDS instance does not have deletion protection enabled', region, instance.DBInstanceArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
