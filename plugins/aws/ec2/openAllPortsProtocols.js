var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Open All Ports Protocols',
    category: 'EC2',
    description: 'Determine if security group has all ports or protocols open to the public',
    more_info: 'Security groups should be created on a per-service basis and avoid allowing all ports or protocols.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html',
    recommended_action: 'Modify the security group to specify a specific port and protocol to allow.',
    apis: ['EC2:describeSecurityGroups', 'EC2:describeNetworkInterfaces', 'Lambda:listFunctions'],
    settings: {
        ec2_skip_unused_groups: {
            name: 'EC2 Skip Unused Groups',
            description: 'Skip checking ports for unused security groups',
            regex: '^(true|false)$',
            default: 'flase',
        }
    },
    compliance: {
        hipaa: 'HIPAA requires strict access controls to networks and services ' +
                'processing sensitive data. Security groups are the built-in ' +
                'method for restricting access to AWS services and should be ' +
                'configured to allow least-privilege access.',
        pci: 'PCI has explicit requirements around firewalled access to systems. ' +
             'Security groups should be properly secured to prevent access to ' +
             'backend services.'
    },

    run: function(cache, settings, callback) {
        var config = {
            ec2_skip_unused_groups: settings.ec2_skip_unused_groups || this.settings.ec2_skip_unused_groups.default,
        };

        config.ec2_skip_unused_groups = (config.ec2_skip_unused_groups == 'true');
        
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

            var found = false;
            var groups = describeSecurityGroups.data;
            var usedGroup = false;
            if (config.ec2_skip_unused_groups) {
                var usedGroups = helpers.getUsedSecurityGroups(cache, results, region, rcb);
            }

            for (var g in groups) {
                var strings = [];
                var resource = 'arn:aws:ec2:' + region + ':' +
                               groups[g].OwnerId + ':security-group/' +
                               groups[g].GroupId;

                if (config.ec2_skip_unused_groups) {
                    if (groups[g].GroupId && !usedGroups.includes(groups[g].GroupId)) {
                        helpers.addResult(results, 0, `Security Group: ${groups[g].GroupId} is not in use`,
                            region, resource);
                        usedGroup = true;
                        continue;
                    }
                }

                for (var p in groups[g].IpPermissions) {
                    var permission = groups[g].IpPermissions[p];

                    for (var k in permission.IpRanges) {
                        var range = permission.IpRanges[k];

                        if (range.CidrIp === '0.0.0.0/0') {
                            if (!permission.FromPort && (!permission.ToPort || permission.ToPort === 65535)) {
                                var string = 'all ports open to 0.0.0.0/0';
                                if (strings.indexOf(string) === -1) strings.push(string);
                                found = true;
                            }

                            if (permission.IpProtocol === '-1') {
                                var stringO = 'all protocols open to 0.0.0.0/0';
                                if (strings.indexOf(stringO) === -1) strings.push(stringO);
                                found = true;
                            }
                        }
                    }

                    for (var l in permission.Ipv6Ranges) {
                        var rangeV6 = permission.Ipv6Ranges[l];

                        if (rangeV6.CidrIpv6 === '::/0') {
                            if (!permission.FromPort && (!permission.ToPort || permission.ToPort === 65535)) {
                                var stringV6 = 'all ports open to ::/0';
                                if (strings.indexOf(stringV6) === -1) strings.push(stringV6);
                                found = true;
                            }

                            if (permission.IpProtocol === '-1') {
                                var stringP = 'all protocols open to ::/0';
                                if (strings.indexOf(stringP) === -1) strings.push(stringP);
                                found = true;
                            }
                        }
                    }
                }

                if (strings.length) {
                    helpers.addResult(results, 2,
                        'Security group: ' + groups[g].GroupId +
                        ' (' + groups[g].GroupName +
                        ') has ' + strings.join(' and '), region,
                        resource);
                }
            }

            if (!found && !usedGroup) {
                helpers.addResult(results, 0, 'No public open ports found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
