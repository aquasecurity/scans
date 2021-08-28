var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Shielded VM Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures that instances are configured with the shielded VM enabled',
    more_info: 'Shielded VM option should be configured to defend against the security attacks on the instances.',
    link: 'https://cloud.google.com/security/shielded-cloud/shielded-vm',
    recommended_action: 'Enable the shielded VM for all the instances for security reasons.',
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
                    helpers.addResult(results, 3, 'Unable to query instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);

                    if (instance.shieldedInstanceConfig &&
                        instance.shieldedInstanceConfig.enableVtpm &&
                        instance.shieldedInstanceConfig.enableIntegrityMonitoring) {
                        helpers.addResult(results, 0,
                            'Shielded VM security is enabled for the the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Shielded VM security is not enabled for the the instance', region, resource);
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
