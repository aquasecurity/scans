var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS SQL Audit Log Retention Period',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure that RDS DB instances SQL Audit Log retention period is configured to be greater than set days limit',
    more_info: 'RDS instances provides auditing feature that can be used to log all the events and activities which can be used later in case of any suspicions or security reasons.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/118678.htm',
    recommended_action: 'Modify RDS DB instances to set SQL Audit Log retention period to be greater than set days limit',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeSQLCollectorRetention', 'STS:GetCallerIdentity'],
    settings: {
        sqlAuditRetentionPeriod: {
            name: 'SQL Audit Retention Period ',
            description: 'Number of days for which SQL Audit logs will be retained',
            regex: '^(30|180|365|1095|1825)$',
            default: '180',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var defaultRegion = helpers.defaultRegion(settings);
        var sqlAuditRetentionPeriod = parseInt(settings.sqlAuditRetentionPeriod || this.settings.sqlAuditRetentionPeriod.default);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'DescribeDBInstances', region]);

            if (!describeDBInstances) {
                return rcb();
            }

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query RDS DB instances: ${helpers.addError(describeDBInstances)}`,
                    region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS DB instances found', region);
                return rcb();
            }

            async.each(describeDBInstances.data, function(instance, cb){
                if (!instance.DBInstanceId) return cb();

                var resource = helpers.createArn('rds', accountId, 'instance', instance.DBInstanceId, region);

                var describeSqlAuditRetention = helpers.addSource(cache, source,
                    ['rds', 'DescribeSQLCollectorRetention', region, instance.DBInstanceId]);

                if (!describeSqlAuditRetention || describeSqlAuditRetention.err || !describeSqlAuditRetention.data) {
                    helpers.addResult(results, 3,
                        `Unable to query DB sql audit log retention: ${helpers.addError(describeSqlAuditRetention)}`,
                        region, resource);
                    return cb();
                }

                const currentRetentionPeriod = describeSqlAuditRetention.data.ConfigValue ?
                    parseInt(describeSqlAuditRetention.data.ConfigValue) : 0;

                if (currentRetentionPeriod >= sqlAuditRetentionPeriod) {
                    helpers.addResult(results, 0,
                        `RDS DB instance sql audit log retention is ${currentRetentionPeriod} which is greater than or equal to ${sqlAuditRetentionPeriod} days`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `RDS DB instance sql audit log retention is ${currentRetentionPeriod} which is lesser than ${sqlAuditRetentionPeriod} days`,
                        region, resource);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};