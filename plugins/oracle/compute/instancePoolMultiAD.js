var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Instance Pool Multiple AD',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures instance pools are launched in multiple availability domains.',
    more_info: 'Launching instance pools in multiple availability domains follows best practices by creating highly available resources.',
    recommended_action: 'When launching instance pools, Add multiple availability domains.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm',
    apis: ['instancePool:list'],

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
                    helpers.addResult(results, 0, 'No instance pools found', region);
                    return rcb();
                }

                instancePools.data.forEach(instancePool => {
                    if (instancePool.availabilityDomains &&
                        instancePool.availabilityDomains.length === 1) {
                            var availabilityDomains = Object.values(instancePool.availabilityDomains).join(', ');
                            helpers.addResult(results, 2, 
                                `Instance pool is only in one availability domain: ${availabilityDomains}`, region, instancePool.id);
                    } else if (instancePool.availabilityDomains &&
                        instancePool.availabilityDomains.length > 1) {
                            var availabilityDomains = Object.values(instancePool.availabilityDomains).join(', ');
                            helpers.addResult(results, 0, 
                                `Instance pool is in multiple availability domains: ${availabilityDomains}`, region, instancePool.id);
                    } else {
                        helpers.addResult(results, 2,
                            'No availability domains', region, instancePool.id);
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