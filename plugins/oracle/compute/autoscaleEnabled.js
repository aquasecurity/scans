var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Autoscale Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures autoscaling is enabled on instance pools.',
    more_info: 'Enabling autoscaling increases efficiency and improves cost management for resources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/autoscalinginstancepools.htm',
    recommended_action: 'Enable autoscaling on all instance pools',
    apis: ['instance:list','instancePool:list', 'autoscaleConfiguration:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.instancePool, function(region, rcb){
            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instancePools = helpers.addSource(cache, source,
                    ['instancePool', 'list', region]);

                if (!instancePools) return rcb();

                if (instancePools.err || !instancePools.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instance pools: ' + helpers.addError(instancePools), region);
                    return rcb();
                }

                if (!instancePools.data.length) {
                    helpers.addResult(results, 0, 'No instance pool found', region);
                    return rcb()
                }

                var autoscaleConfigurations = helpers.addSource(cache, source,
                    ['autoscaleConfiguration', 'list', region]);

                if (!autoscaleConfigurations || autoscaleConfigurations.err || !autoscaleConfigurations.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for autoscaling configurations: ' + helpers.addError(autoscaleConfigurations), region);
                    return rcb();
                }

                if (!autoscaleConfigurations.data.length) {
                    helpers.addResult(results, 2, 'No autoscaling configurations found', region);
                    return rcb();
                }

                var enabledInstancePools = [];
                autoscaleConfigurations.data.forEach(autoscaleConfiguration => {
                    if (autoscaleConfiguration.isEnabled &&
                        autoscaleConfiguration.resource &&
                        autoscaleConfiguration.resource.id) {
                        enabledInstancePools.push(autoscaleConfiguration.resource.id);
                    }
                });

                instancePools.data.forEach(instancePool => {
                    if (enabledInstancePools.indexOf(instancePool.id) > -1) {
                        helpers.addResult(results, 0,
                            'The instance pool has autoscaling enabled', region, instancePool.id);
                    } else {
                        helpers.addResult(results, 2,
                            'The instance pool has autoscaling disabled', region, instancePool.id);
                    }
                });
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};