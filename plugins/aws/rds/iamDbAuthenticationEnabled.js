var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS IAM Database Authentication Enabled',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures IAM Database Authentication is enabled for RDS database instances to manage database access',
    more_info: 'AWS Identity and Access Management (IAM) can be used to authenticate to your RDS DB instances.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html',
    recommended_action: 'Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.',
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
                    `Unable to query for RDS instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            describeDBInstances.data.forEach(instance => {
                if (!instance.DBInstanceArn || !instance.Engine) return;

                if (['postgres', 'mysql'].includes(instance.Engine)) {
                    if (instance.IAMDatabaseAuthenticationEnabled) {
                        helpers.addResult(results, 0,
                            'RDS instance has IAM Database Authentication enabled', region, instance.DBInstanceArn);
                    } else {
                        helpers.addResult(results, 2,
                            'RDS instance does not have IAM Database Authentication enabled', region, instance.DBInstanceArn);
                    }
                } else {
                    helpers.addResult(results, 0,
                        `RDS instance engine type ${instance.Engine} does not support IAM database authentication`, region, instance.DBInstanceArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};