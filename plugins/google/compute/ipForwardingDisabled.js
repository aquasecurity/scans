var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'IP Forwarding Disabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures that IP forwarding is disabled on all instances',
    more_info: 'Disabling IP forwarding ensures that the instance only sends and receives packets with matching destination or source IPs.',
    link: 'https://cloud.google.com/vpc/docs/using-routes',
    recommended_action: 'IP forwarding settings can only be chosen when creating a new instance. Delete the affected instances and redeploy with IP forwarding disabled.',
    apis: ['instances:compute:list', 'projects:get'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone ]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (instance.canIpForward) {
                        helpers.addResult(results, 2,
                            'Instance has IP forwarding enabled', region, resource);   
                    } else {
                        helpers.addResult(results, 0,
                            'Instance does not have IP forwarding enabled', region, resource);   
                    }
                });

                zcb();
            }, function() {
                if (noInstances.length) {
                    helpers.addResult(results, 0, `No instances found in following zones: ${noInstances.join(', ')}`, region);
                }
                rcb();
            });

        }, function() {
            callback(null, results, source);
        });
    }
}