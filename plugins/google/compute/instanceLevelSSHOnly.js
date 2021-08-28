var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Level SSH Only',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures that instances are not configured to allow project-wide SSH keys',
    more_info: 'To support the principle of least privilege and prevent potential privilege escalation it is recommended that instances are not give access to project-wide SSH keys through instance metadata.',
    link: 'https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys',
    recommended_action: 'Ensure project-wide SSH keys are blocked for all instances.',
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
                    ['instances', 'compute','list', zone]);

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
                    var found;
                    if (instance.metadata &&
                        instance.metadata.items &&
                        instance.metadata.items.length) {
                        found = instance.metadata.items.find(metaItem => metaItem.key === 'block-project-ssh-keys' &&
                            metaItem.value && metaItem.value.toUpperCase() === 'TRUE');
                    }

                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (found) {
                        helpers.addResult(results, 0,
                            'Block project-wide SSH keys is enabled for the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Block project-wide SSH keys is disabled for the instance', region, resource);
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
