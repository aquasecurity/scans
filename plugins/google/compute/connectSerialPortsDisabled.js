var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Connect Serial Ports Disabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures connecting to serial ports is not enabled for VM instances',
    more_info: 'The serial console does not allow restricting IP Addresses, which allows any IP address to connect to instance and should therefore be disabled.',
    link: 'https://cloud.google.com/compute/docs/instances/interacting-with-serial-console',
    recommended_action: 'Ensure the Enable Connecting to Serial Ports option is disabled for all compute instances.',
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
            var noInstances = [];
            var zones = regions.zones;
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
                    let found = false;
                    if (instance.metadata &&
                        instance.metadata.items &&
                        instance.metadata.items.length) {
                        found = instance.metadata.items.find(item => item.key && item.key.toLowerCase() == 'serial-port-enable' &&
                            item.value && item.value.toLowerCase() === 'true');
                    }

                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (found) {
                        helpers.addResult(results, 2,
                            'Connecting to Serial Ports is enabled for the instance', region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Connecting to Serial Ports is disabled for the instance', region, resource);
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
};