var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS Auditing Enabled',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure that RDS DB instances events and activities are being logged to help fix any suspicious activities or security issues.',
    more_info: 'RDS instances provides auditing feature that can be used to log all the events and activities which can be used later in case of any suspicions or security reasons.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/118678.htm',
    recommended_action: 'Modify RDS DB instances to enable the auditing',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeSQLCollectorPolicy', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var defaultRegion = helpers.defaultRegion(settings);

        var unsupportedEngines = ['sqlserver 2012', 'sqlserver 2016', 'sqlserver 2017', 'mariadb tx'];
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

                let instanceEngine = (instance.Engine && instance.EngineVersion) ? `${instance.Engine.toLowerCase()} ${instance.EngineVersion}` : '';

                if (unsupportedEngines.includes(instanceEngine)) {
                    helpers.addResult(results, 0,
                        `SQL auditing is not supported for ${instanceEngine} engine type`,
                        region, resource);
                    return cb();
                }

                var describeSqlAudit = helpers.addSource(cache, source,
                    ['rds', 'DescribeSQLCollectorPolicy', region, instance.DBInstanceId]);

                if (!describeSqlAudit || describeSqlAudit.err || !describeSqlAudit.data) {
                    helpers.addResult(results, 3,
                        `Unable to query DB sql auditing policy: ${helpers.addError(describeSqlAudit)}`,
                        region, resource);
                    return cb();
                }

                if (describeSqlAudit.data.SQLCollectorStatus == 'Enable') {
                    helpers.addResult(results, 0,
                        'RDS DB instance have sql auditing enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'RDS DB instance does not have sql auditing enabled',
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