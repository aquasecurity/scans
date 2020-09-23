var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Launch Configuration Referencing Missing Security Groups',
    category: 'AutoScaling',
    description: 'Ensures that Auto Scaling Launch Configurations are not utilizing missing Security Groups.',
    more_info: 'Auto Scaling launch configuration should utilize an active security group to ensure safety of managed instances.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/GettingStartedTutorial.html',
    recommended_action: 'Ensure that the launch configuration security group has not been deleted. If so, remove it from launch configurations',
    apis: ['AutoScaling:describeLaunchConfigurations', 'EC2:describeSecurityGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.autoscaling, function(region, rcb){
            var describeLaunchConfigurations = helpers.addSource(cache, source,
                ['autoscaling', 'describeLaunchConfigurations', region]);

            var describeSecurityGroups = helpers.addSource(cache, source,
                ['ec2', 'describeSecurityGroups', region]);

            if (!describeLaunchConfigurations) return rcb();

            if (describeLaunchConfigurations.err || !describeLaunchConfigurations.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Auto Scaling launch configurations: ${helpers.addError(describeLaunchConfigurations)}`,
                    region);
                return rcb();
            }

            if (!describeLaunchConfigurations.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling launch configurations found', region);
                return rcb();
            }

            if (!describeSecurityGroups) return rcb();

            if (describeSecurityGroups.err || !describeSecurityGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EC2 security groups: ${helpers.addError(describeSecurityGroups)}`, region);
                return rcb();
            }

            var securityGroups = [];
            if (describeSecurityGroups.data.length) {
                describeSecurityGroups.data.forEach(function(sg){
                    securityGroups.push(sg.GroupId);
                });
            }

            describeLaunchConfigurations.data.forEach(function(config){
                var resource = config.LaunchConfigurationARN;

                if (!config.SecurityGroups || !config.SecurityGroups.length) {
                    helpers.addResult(results, 2,
                        `Auto Scaling launch configuration ${config.LaunchConfigurationName} does not utilize any security group`,
                        region, resource);
                }
                else {
                    if (!securityGroups.length) {
                        helpers.addResult(results, 2, 'No EC2 security groups found', region);
                        return rcb();
                    }

                    var missingSecurityGroups = [];
                    config.SecurityGroups.forEach(function(group){
                        if (!securityGroups.includes(group)) {
                            missingSecurityGroups.push(group);
                        }
                    });

                    if(missingSecurityGroups.length > 0) {
                        helpers.addResult(results, 2,
                            `Auto Scaling launch configuration utilizes "${missingSecurityGroups.join(' , ')}" missing EC2 security groups`,
                            region, resource);
                    }
                    else {
                        helpers.addResult(results, 0,
                            `Auto Scaling launch configuration "${config.LaunchConfigurationName}" does not utilize missing EC2 security group`,
                            region, resource);
                    }
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
