var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS DocumentDB Minor Version Upgrade',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures Auto Minor Version Upgrade is enabled on RDS and DocumentDB databases',
    more_info: 'RDS supports automatically upgrading the minor version of the database, which should be enabled to ensure security fixes are quickly deployed.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html#USER_UpgradeDBInstance.Upgrading.AutoMinorVersionUpgrades',
    recommended_action: 'Enable automatic minor version upgrades on RDS and DocumentDB databases',
    apis: ['RDS:describeDBInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source, ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) {
                return rcb();
            }

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3, `Unable to query for RDS/DocumentDB instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS/DocumentDB instances found');
                return rcb();
            }

            for (var i in describeDBInstances.data) {
                var db = describeDBInstances.data[i];

                if (db.AutoMinorVersionUpgrade) {
                    helpers.addResult(results, 0, 'Auto Minor Version Upgrade is enabled', region, db.DBInstanceArn);
                } else {
                    helpers.addResult(results, 2, 'Auto Minor Version Upgrade is not enabled', region, db.DBInstanceArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
