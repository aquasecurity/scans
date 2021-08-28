var async = require('async');
var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RDS Public Access',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure that RDS DB instances are not publicly accessible.',
    more_info: 'Enabling public access increase chances of data insecurity. Public access should always be disabled and only know IP addresses should be whitelisted.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/26198.htm',
    recommended_action: 'Modify security settings for RDS DB instances to disable the public access.',
    apis: ['RDS:DescribeDBInstances', 'RDS:DescribeDBInstanceIPArrayList', 'STS:GetCallerIdentity'],

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

                var resource = helpers.createArn('rds', accountId, 'instance', instance.DBInstanceId, region);

                var describeInstanceWhitelist = helpers.addSource(cache, source,
                    ['rds', 'DescribeDBInstanceIPArrayList', region, instance.DBInstanceId]);

                if (!describeInstanceWhitelist || describeInstanceWhitelist.err || !describeInstanceWhitelist.data) {
                    helpers.addResult(results, 3,
                        `Unable to query DB IP Array List: ${helpers.addError(describeInstanceWhitelist)}`,
                        region, resource);
                    return cb();
                }

                if (describeInstanceWhitelist.data.Items &&
                    describeInstanceWhitelist.data.Items.DBInstanceIPArray &&
                    describeInstanceWhitelist.data.Items.DBInstanceIPArray.length) {
                    let ipArray =  describeInstanceWhitelist.data.Items.DBInstanceIPArray;
                    let found = ipArray.find(ipObject => ipObject.SecurityIPList && ipObject.SecurityIPList.includes('0.0.0.0'));

                    if (found) {
                        helpers.addResult(results, 2,
                            'RDS DB instance is publicly accessible',
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'RDS DB instance is not publicly accessible',
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'RDS DB instance is not publicly accessible',
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
