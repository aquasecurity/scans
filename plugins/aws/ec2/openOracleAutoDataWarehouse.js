var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open Oracle Auto Data Warehouse',
    category: 'EC2',
    description: 'Determine if TCP port 1522 for Oracle Auto Data Warehouse is open to the public',
    more_info: 'While some ports such as HTTP and HTTPS are required to be open \
        to the public to function properly, more sensitive services such as Oracle Auto Data Warehouse \
        should be restricted to known IP addresses.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Restrict TCP ports 1522 to known IP addresses',
    apis: ['EC2:describeSecurityGroups', 'EC2:describeNetworkInterfaces', 'Lambda:listFunctions'],
    settings: {
        ec2_skip_unused_groups: {
            name: 'EC2 Skip Unused Groups',
            description: 'Skip checking ports for unused security groups',
            regex: '^(true|false)$',
            default: 'false',
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            ec2_skip_unused_groups: settings.ec2_skip_unused_groups || this.settings.ec2_skip_unused_groups.default,
        };

        config.ec2_skip_unused_groups = (config.ec2_skip_unused_groups == 'true');

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var ports = {
            'tcp': [1522]
        };

        var service = 'Oracle Auto Data Warehouse';

        async.each(regions.ec2, function(region, rcb){
            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
                return rcb();
            }

            if (!describeSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No security groups present', region);
                return rcb();
            }

            helpers.findOpenPorts(describeSecurityGroups.data, ports, service, region, results, cache, config, rcb);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};