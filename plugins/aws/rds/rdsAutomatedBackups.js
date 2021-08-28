var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Automated Backups',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures automated backups are enabled for RDS instances',
    more_info: 'AWS provides a simple method of backing up RDS instances at a regular interval. This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.',
    link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
    recommended_action: 'Enable automated backups for the RDS instance',
    apis: ['RDS:describeDBInstances'],
    settings: {
        rds_backup_period: {
            name: 'RDS Backup Period',
            description: 'Return a passing result when RDS backup retention period is higher than this number of days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 6
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            rds_backup_period: settings.rds_backup_period || this.settings.rds_backup_period.default
        };

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

            for (var i in describeDBInstances.data) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var db = describeDBInstances.data[i];
                var dbResource = db.DBInstanceArn;

                // skip if it is read only replica Source Identifier for PostgreSQL
                if (db.Engine === 'postgresql' && db.ReadReplicaSourceDBInstanceIdentifier){
                    continue;
                }

                if (db.BackupRetentionPeriod && db.BackupRetentionPeriod > config.rds_backup_period) {
                    helpers.addResult(results, 0,
                        'Automated backups are enabled with sufficient retention (' + db.BackupRetentionPeriod + ' days)',
                        region, dbResource, custom);
                } else if (db.BackupRetentionPeriod) {
                    helpers.addResult(results, 1,
                        'Automated backups are enabled but do not have sufficient retention (' + db.BackupRetentionPeriod + ' days)',
                        region, dbResource, custom);
                } else {
                    helpers.addResult(results, 2,
                        'Automated backups are not enabled',
                        region, dbResource, custom);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
