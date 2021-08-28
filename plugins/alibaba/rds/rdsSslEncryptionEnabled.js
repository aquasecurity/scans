var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS SSL Encryption Enabled',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure that RDS instances enforce all incoming connections to use SSL.',
    more_info: 'To enhance link security, you should enable Secure Sockets Layer (SSL) encryption for RDS instances. ' + 
        'SSL is used on the transport layer to encrypt network connections. SSL not only increases the security and integrity of communication data, but also increases the response time for network connection.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/32474.htm',
    recommended_action: 'Enable SSL ecnryption for RDS instances',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeDBInstanceSSL', 'STS:GetCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'RDS SSL connection should be used to ensure internal ' +
            'services are always connecting over a secure channel.',
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var defaultRegion = helpers.defaultRegion(settings);

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

                var instanceSslInfo = helpers.addSource(cache, source,
                    ['rds', 'DescribeDBInstanceSSL', region, instance.DBInstanceId]);
                
                var resource = helpers.createArn('rds', accountId, 'instance', instance.DBInstanceId, region);

                if (!instanceSslInfo || instanceSslInfo.err || !instanceSslInfo.data) {
                    helpers.addResult(results, 3,
                        `Unable to query RDS instance SSL info: ${helpers.addError(instanceSslInfo)}`,
                        region, resource);
                    return cb();
                }

                if (instanceSslInfo.data.RequireUpdate && instanceSslInfo.data.RequireUpdate.toLowerCase() == 'yes') {
                    helpers.addResult(results, 0,
                        'RDS instance has SSL encryption enabled', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'RDS instance does not have SSL encryption enabled', region, resource);
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