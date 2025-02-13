var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused Open Ports',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Detects open ports in security groups that are not associated with any running service on the instance.',
    more_info: 'Unused open ports can pose a security risk as they might be exploited by attackers if not properly managed.',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html',
    recommended_action: 'Close unused ports in the security group or ensure the associated service is properly configured.',
    apis: ['EC2:describeSecurityGroups', 'EC2:describeInstances'],
    realtime_triggers: ['ec2:CreateSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress', 'ec2:ModifySecurityGroupRules', 'ec2:RevokeSecurityGroupIngress', 'ec2:DeleteSecurityGroup'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function (region, rcb) {
            processRegion(region, cache, settings, results, source, rcb);
        }, function () {
            callback(null, results, source);
        });
    }
};

/**
 * Process a single AWS region to check for unused open ports.
 */
function processRegion(region, cache, settings, results, source, rcb) {
    var describeInstances = helpers.addSource(cache, source, ['ec2', 'describeInstances', region]);
    var describeSecurityGroups = helpers.addSource(cache, source, ['ec2', 'describeSecurityGroups', region]);

    if (!describeInstances || !describeSecurityGroups) return rcb();

    if (hasError(describeInstances) || hasError(describeSecurityGroups)) {
        helpers.addResult(
            results,
            3,
            `Unable to query for instances or security groups: ${helpers.addError(describeInstances || describeSecurityGroups)}`,
            region
        );
        return rcb();
    }

    var instancePorts = getInstancePorts(describeInstances.data, describeSecurityGroups.data);

    analyzeSecurityGroups(instancePorts, describeSecurityGroups.data, region, results);

    rcb();
}

/**
 * Check if the AWS API response has an error or missing data.
 */
function hasError(response) {
    return response.err || !response.data;
}

/**
 * Collect used ports for each running instance.
 */
function getInstancePorts(instances, securityGroups) {
    var instancePorts = {};

    instances.forEach(function (instance) {
        if (!instance.State || instance.State.Name !== 'running') return;

        var instanceId = instance.InstanceId;
        instancePorts[instanceId] = collectUsedPorts(instance, securityGroups);
    });

    return instancePorts;
}

/**
 * Collect used ports from instance security groups.
 */
function collectUsedPorts(instance, securityGroups) {
    var usedPorts = [];

    if (instance.SecurityGroups) {
        instance.SecurityGroups.forEach(function (group) {
            var securityGroup = securityGroups.find(g => g.GroupId === group.GroupId);

            if (securityGroup && securityGroup.IpPermissions) {
                securityGroup.IpPermissions.forEach(function (permission) {
                    if (permission.FromPort && permission.ToPort) {
                        for (let port = permission.FromPort; port <= permission.ToPort; port++) {
                            if (!usedPorts.includes(port)) {
                                usedPorts.push(port);
                            }
                        }
                    }
                });
            }
        });
    }

    return usedPorts;
}

/**
 * Analyze security groups to find unused open ports.
 */
function analyzeSecurityGroups(instancePorts, securityGroups, region, results) {
    securityGroups.forEach(function (group) {
        if (!group.IpPermissions) return;

        var resource = `arn:${helpers.defaultPartition({})}:ec2:${region}:${group.OwnerId}:security-group/${group.GroupId}`;
        var unusedPorts = getUnusedPorts(group, instancePorts);

        if (unusedPorts.length) {
            helpers.addResult(
                results,
                2,
                `Security group "${group.GroupName}" has unused open ports: ${unusedPorts.join(', ')}`,
                region,
                resource
            );
        } else {
            helpers.addResult(
                results,
                0,
                `Security group "${group.GroupName}" has no unused open ports`,
                region,
                resource
            );
        }
    });
}

/**
 * Get unused open ports for a security group.
 */
function getUnusedPorts(group, instancePorts) {
    var unusedPorts = [];

    group.IpPermissions.forEach(function (permission) {
        if (permission.IpRanges) {
            permission.IpRanges.forEach(function (range) {
                if (range.CidrIp === '0.0.0.0/0') {
                    for (let port = permission.FromPort; port <= permission.ToPort; port++) {
                        if (!isPortUsed(port, instancePorts) && !unusedPorts.includes(port)) {
                            unusedPorts.push(port);
                        }
                    }
                }
            });
        }
    });

    return unusedPorts;
}

/**
 * Check if a port is used by any instance.
 */
function isPortUsed(port, instancePorts) {
    for (var instanceId in instancePorts) {
        if (instancePorts[instanceId].includes(port)) {
            return true;
        }
    }
    return false;
}

