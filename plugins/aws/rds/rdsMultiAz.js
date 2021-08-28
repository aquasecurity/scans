var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Multiple AZ',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures that RDS instances are created to be cross-AZ for high availability.',
    more_info: 'Creating RDS instances in a single AZ creates a single point of failure for all systems relying on that database. All RDS instances should be created in multiple AZs to ensure proper failover.',
    link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html',
    recommended_action: 'Modify the RDS instance to enable scaling across multiple availability zones.',
    apis: ['RDS:describeDBInstances'],
    settings: {
        rds_multi_az_ignore_replicas: {
            name: 'RDS Multiple AZ Ignore Replicas',
            description: 'When set to true, RDS read replicas which does not require multi-AZ configuration will PASS',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            rds_multi_az_ignore_replicas: settings.rds_multi_az_ignore_replicas || this.settings.rds_multi_az_ignore_replicas.default
        };

        config.rds_multi_az_ignore_replicas = (config.rds_multi_az_ignore_replicas == 'true');

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb){
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

            // loop through Rds Instances
            describeDBInstances.data.forEach(function(Rds){
                if (Rds.Engine === 'aurora' ||
                    Rds.Engine === 'aurora-postgresql' ||
                    Rds.Engine === 'aurora-mysql') {
                    helpers.addResult(results, 0,
                        'RDS Aurora instances are multi-AZ',
                        region, Rds.DBInstanceArn);
                } else if (Rds.Engine === 'docdb') {
                    helpers.addResult(results, 0,
                        'RDS DocDB instances multi-AZ property is not supported in this context',
                        region, Rds.DBInstanceArn);
                } else if (Rds.MultiAZ){
                    helpers.addResult(results, 0,
                        'RDS instance has multi-AZ enabled',
                        region, Rds.DBInstanceArn);
                } else {
                    if (config.rds_multi_az_ignore_replicas &&
                        Rds.ReadReplicaSourceDBInstanceIdentifier) {
                        helpers.addResult(results, 0,
                            'RDS instance does not have multi-AZ enabled but is a read replica',
                            region, Rds.DBInstanceArn, custom);
                    } else {
                        helpers.addResult(results, 2,
                            'RDS instance does not have multi-AZ enabled',
                            region, Rds.DBInstanceArn, custom);
                    }
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
