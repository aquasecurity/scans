var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Agent Auto Update Enabled',
    category: 'SSM',
    description: 'Ensures the SSM agent is configured to automatically update to new versions',
    more_info: 'To ensure the latest version of the SSM agent is installed, it should be configured to consume automatic updates.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html',
    recommended_action: 'Update the SSM agent configuration for all managed instances to use automatic updates.',
    apis: ['SSM:describeInstanceInformation', 'SSM:listAssociations'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ssm, function(region, rcb){
            var describeInstanceInformation = helpers.addSource(cache, source,
                ['ssm', 'describeInstanceInformation', region]);

            var listAssociations = helpers.addSource(cache, source,
                ['ssm', 'listAssociations', region]);

            if (!describeInstanceInformation || !listAssociations) return rcb();

            if (describeInstanceInformation.err || !describeInstanceInformation.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SSM instance information: ' + helpers.addError(describeInstanceInformation), region);
                return rcb();
            }
            
            if (listAssociations.err || !listAssociations.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SSM Associations List: ' + helpers.addError(listAssociations), region);
                return rcb();
            }

            if(!describeInstanceInformation.data.length) {
                helpers.addResult(results, 2,
                    'No instance found in SSM instance information', region);
                return rcb();
            }
            
            if(!listAssociations.data.length) {
                helpers.addResult(results, 2,
                    'No SSM AWS-UpdateSSMAgent associations found', region);
                return rcb();
            }

            var associatedInstances = [];

            listAssociations.data.forEach(function(association){
                if (association.Name === 'AWS-UpdateSSMAgent' && association.Targets && association.Targets.length) {
                    association.Targets.forEach(function(target){
                        if(target.Key && target.Key === 'InstanceIds' && target.Values && target.Values.length) {
                            target.Values.forEach(function(instanceId){
                                if(!associatedInstances.includes(instanceId) && association.ScheduleExpression){
                                    associatedInstances.push(instanceId);
                                }
                            });
                        }
                    });
                }
            });

            describeInstanceInformation.data.forEach(function(instance) {
                var resource = instance.InstanceId;
                if (associatedInstances.includes(resource) || associatedInstances.includes('*')) {
                    helpers.addResult(results, 0, 
                        'Instance has SSM Agent auto update enabled', region, resource);
                }
                else {
                    helpers.addResult(results, 2, 
                        'Instance does not have SSM Agent auto update enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};