var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS Transparent Data Encryption Enabled',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure that RDS instances have Transparent Data Encryption enabled.',
    more_info: 'TDE should be enabled to protect against the threat of malicious activities. Real-time encryption and decryption of the database,' +  
        'associated backups, and log files is performed at rest without requiring any change to the application.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/26256.htm',
    recommended_action: 'Enable TDE for RDS instances',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeDBInstanceTDE', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var defaultRegion = helpers.defaultRegion(settings);

        var supportedEngines = ['sqlserver 2012_ent_ag', 'sqlserver 2016_ent_ag', 'sqlserver 2017_ent_ag', 'sqlserver 2019_ent_ag', 'mysql 5.6'];
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

                if (!supportedEngines.includes(instanceEngine)) {
                    helpers.addResult(results, 0,
                        `TDE is not supported for ${instanceEngine} engine type`,
                        region, resource);
                    return cb();
                }

                var describeDbInstanceTde = helpers.addSource(cache, source,
                    ['rds', 'DescribeDBInstanceTDE', region, instance.DBInstanceId]);

                if (!describeDbInstanceTde || describeDbInstanceTde.err || !describeDbInstanceTde.data) {
                    helpers.addResult(results, 3,
                        `Unable to query RDS DB instance TDE: ${helpers.addError(describeDbInstanceTde)}`,
                        region, resource);
                    return cb();
                }

                if (describeDbInstanceTde.data.TDEStatus && describeDbInstanceTde.data.TDEStatus.toUpperCase() == 'ENABLED') {
                    helpers.addResult(results, 0,
                        'RDS DB instance has TDE enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'RDS DB instance does not have TDE enabled',
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