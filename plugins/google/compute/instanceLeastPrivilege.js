var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VM Instances Least Privilege',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures that instances are not configured to use the default service account with full access to all cloud APIs',
    more_info: 'To support the principle of least privilege and prevent potential privilege escalation, it is recommended that instances are not assigned to the default service account, Compute Engine default service account with a scope allowing full access to all cloud APIs.',
    link: 'https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances',
    recommended_action: 'For all instances, if the default service account is used, ensure full access to all cloud APIs is not configured.',
    apis: ['instances:compute:list', 'projects:get'],
    compliance: {
        pci: 'PCI has explicit requirements around default accounts and ' +
            'resources. PCI recommends removing all default accounts, ' +
            'only enabling necessary services as required for the function ' +
            'of the system'
    },

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
                    let found = false;
                    if (instance.serviceAccounts && instance.serviceAccounts.length) {
                        found = instance.serviceAccounts.find(serviceAccount => serviceAccount.scopes &&
                            serviceAccount.scopes.indexOf('https://www.googleapis.com/auth/cloud-platform') > -1);
                    }

                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);

                    if (found) {
                        helpers.addResult(results, 2,
                            `Instance Service account has full access` , region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Instance Service account follows least privilege' , region, resource);
                    }
                });
                return zcb();
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
