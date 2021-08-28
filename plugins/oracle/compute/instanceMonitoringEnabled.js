var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Instance Monitoring Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures monitoring is enabled for instances.',
    more_info: 'Enabling instance monitoring allows for metrics to be collected on the instance. Following security best practices. ',
    recommended_action: 'When creating a new instance, ensure monitoring is enabled under advanced settings.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Compute/Tasks/enablingmonitoring.htm',
    apis: ['instance:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.instance, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instances = helpers.addSource(cache, source,
                    ['instance', 'list', region]);

                if (!instances) return rcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instances: ' + helpers.addError(instances), region);
                    return rcb();
                }

                if (!instances.data.length) {
                    helpers.addResult(results, 0, 'No instances found', region);
                    return rcb();
                }

                instances.data.forEach(instance => {
                    if (instance.agentConfig &&
                        !instance.agentConfig.isMonitoringDisabled) {
                        helpers.addResult(results, 0, 'Instance monitoring is enabled', region, instance.id);
                    } else {
                        helpers.addResult(results, 2, 'Instance monitoring is disabled', region, instance.id);
                    }
                });
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};