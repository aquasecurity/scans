var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Default Service Account',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures that compute instances are not configured to use the default service account.',
    more_info: 'Default service account has the editor role permissions. Due to security reasons it should not be used for any instance.',
    link: 'https://cloud.google.com/compute/docs/access/service-accounts',
    recommended_action: 'Make sure that compute instances are not using default service account',
    apis: ['instances:compute:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects) return callback(null, results, source);

        if (projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global');
            return callback(null, results, source);
        }

        if (!projects.data.length) {
            helpers.addResult(results, 0, 'No projects found', 'global');
            return callback(null, results, source);
        }

        var defaultServiceAccount = projects.data[0].defaultServiceAccount;
        var project = projects.data[0].name;

        if (!defaultServiceAccount) return callback(null, results, source);

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];
            async.each(zones[region], (zone, zcb) => {
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
                    let found;
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (instance.serviceAccounts &&
                        instance.serviceAccounts.length) {
                        found = instance.serviceAccounts.find(account => account.email == defaultServiceAccount);
                    }
                    if (found) {
                        helpers.addResult(results, 2,
                            'Default service account is used for instance', region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Default service account is not used for instance', region, resource);
                    }
                });
                
                zcb();
            }, function(){
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
