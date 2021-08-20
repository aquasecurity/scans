var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Autoscale Minimum CPU Utilization Target',
    category: 'Compute',
    description: 'Ensure that minimum CPU utilization target is greater or equal than set percentage.',
    more_info: 'The autoscaler treats the target CPU utilization level as a fraction of the average use of all vCPUs over time in the instance group. If the average utilization of your total vCPUs exceeds the target utilization, the autoscaler adds more VM instances. If the average utilization of your total vCPUs is less than the target utilization, the autoscaler removes instances.',
    link: 'https://cloud.google.com/compute/docs/autoscaler/scaling-cpu',
    recommended_action: 'Ensure all instance groups have Minimum CPU Utilization greater than or equal to target value.',
    apis: ['instanceGroups:aggregatedList', 'autoscalers:aggregatedList', 'clusters:list', 'projects:get'],
    settings: {
        minimum_cpu_utilization_target: {
            name: 'Autoscale Minimum CPU Utilization Target',
            description: 'Value between 1-100 for the Autoscale Minimum CPU Utilization Target',
            regex: '^(100|[1-9][0-9]?)$',
            default: 'false',
        }
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var instanceGroupURLObj = {};
        
        var minimum_cpu_utilization_target = settings.minimum_cpu_utilization_target || this.settings.minimum_cpu_utilization_target.default;

        if (minimum_cpu_utilization_target == 'false') return callback(null, results, source);

        minimum_cpu_utilization_target = parseInt(minimum_cpu_utilization_target); 

        let instanceGroupsObj = helpers.addSource(cache, source,
            ['instanceGroups', 'aggregatedList', ['global']]);

        if (!instanceGroupsObj) return callback(null, results, source)

        if (instanceGroupsObj.err || !instanceGroupsObj.data) {
            helpers.addResult(results, 3, 'Unable to query instance groups', 'global', null, null, instanceGroupsObj.err);
            return callback(null, results, source);
        }

        var instanceGroups = Object.values(instanceGroupsObj.data).filter(instanceGroup => {
            return !instanceGroup.warning;
        });

        if (!instanceGroups.length) {
            helpers.addResult(results, 0, 'No instance groups found', 'global');
            return callback(null, results, source);
        }

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;
        let autoscalersObj = helpers.addSource(cache, source,
            ['autoscalers', 'aggregatedList', ['global']]);

        if (autoscalersObj.err || !autoscalersObj.data) {
            helpers.addResult(results, 3, 'Unable to query autoscalers', 'global', null, null, autoscalersObj.err);
        } else {
            var autoscalers = Object.values(autoscalersObj.data).filter(autoscaler => {
                return !autoscaler.warning;
            });

            if (!autoscalers.length) {
                helpers.addResult(results, 0, 'No autoscalers found', 'global');
            }

            async.each(instanceGroups, function (instanceGroupsInLocation, rcb) {
                instanceGroupsInLocation.instanceGroups.forEach(instanceGroup => {
                    let groupLocArr = instanceGroup.zone ? instanceGroup.zone.split('/') :
                        instanceGroup.region ? instanceGroup.region.split('/') : ['global'];
                    let groupLoc = groupLocArr[groupLocArr.length - 1];
                    let resourceType = instanceGroup.zone ? 'zone' :
                        instanceGroup.region ? 'region' : 'global';
                    let resource = helpers.createResourceName('instanceGroups', instanceGroup.name, project, resourceType, groupLoc);
                    let region = (resourceType == 'zone') ? groupLoc.substr(0, groupLoc.length - 2) : groupLoc;

                    if (autoscalers.length) {
                        autoscalers.forEach(scaler => {

                            if (scaler && scaler.autoscalers && scaler.autoscalers.length) {

                                if (instanceGroup && instanceGroup.name) {
                                    let autoScalingData = scaler.autoscalers.find(scalerObj => scalerObj.name == instanceGroup.name)

                                    if (autoScalingData && autoScalingData.autoscalingPolicy &&
                                        autoScalingData.autoscalingPolicy.cpuUtilization && autoScalingData.autoscalingPolicy.cpuUtilization &&
                                        autoScalingData.autoscalingPolicy.cpuUtilization.utilizationTarget) {

                                        if ((autoScalingData.autoscalingPolicy.cpuUtilization.utilizationTarget * 100) >= minimum_cpu_utilization_target) {
                                            helpers.addResult(results, 0,
                                                'Instance group has desired minimum cpu utilization target', region, resource);
                                        } else {
                                            helpers.addResult(results, 2,
                                                'Instance group does not have desired minimum cpu utilization target', region, resource);
                                        }

                                    } else {
                                        helpers.addResult(results, 0,
                                            'No auto scaling policies found for this instance group', region, resource);
                                    }

                                }
                            }
                        })
                    }

                });
                return rcb();
            });
        }
        callback(null, results, source);

    }
};