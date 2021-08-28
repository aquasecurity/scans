var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instances Multi AZ',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures managed instances are regional for availability purposes.',
    more_info: 'Creating instances in a single zone creates a single point of failure for all systems in the VPC. All managed instances should be created as Regional to ensure proper failover.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Launch new instances as regional instance groups.',
    apis: ['instanceGroups:aggregatedList', 'instances:compute:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var region = regions.instanceGroups[0];

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        let instanceGroups = helpers.addSource(cache, source,
            ['instanceGroups', 'aggregatedList', region]);

        if (!instanceGroups) {
            helpers.addResult(results, 3, 'Unable to query instance groups', region);
            return callback(null, results, source);
        } else if (instanceGroups.err || !instanceGroups.data) {
            helpers.addResult(results, 3, 'Unable to query instance groups', region, null, null, instanceGroups.err);
            return callback(null, results, source);
        } else {
            var groupName = [];
            async.each(instanceGroups.data, function (instanceGroup, icb) {
                if (instanceGroup.instanceGroups) {
                    instanceGroup.instanceGroups.forEach(group => {
                        if (group.region) {
                            groupName.push(group.name);
                        }
                    });
                }
                icb();
            }, function () {
                async.each(regions.instances.compute, function (location, loccb) {
                    var noInstances = [];
                    async.each(regions.zones[location], function (loc, lcb) {
                        let instances = helpers.addSource(
                            cache, source, ['instances', 'compute', 'list', loc]);

                        if (!instances) return lcb();

                        if (instances.err || !instances.data) {
                            helpers.addResult(results, 3, 'Unable to query instances: ' + helpers.addError(instances), location);
                            return lcb();
                        }

                        //Looping by zone, ignoring the results
                        if (!instances.data.length) {
                            noInstances.push(loc);
                            return lcb();
                        }

                        for (let instance of instances.data) {
                            if (!instance.name) continue;
                            let resource = helpers.createResourceName('instances', instance.name, project, 'zone', location);
                            var instanceName = instance.name.split('-');
                            instanceName.splice(instanceName.length - 1, 1);
                            instanceName = instanceName.join('-');

                            if (groupName.includes(instanceName)) {
                                helpers.addResult(results, 0,
                                    'Instance is regional and highly available', location, resource);
                            } else {
                                helpers.addResult(results, 2,
                                    'Instance is available in single zone', location, resource);
                            }
                        }
                        lcb();
                    }, function() {
                        if (noInstances.length) {
                            helpers.addResult(results, 0,
                                `No instances found in following zones: ${noInstances.join(', ')}`, location)
                        }
                        loccb();
                    });
                }, function() {
                    callback(null, results, source);
                });
            });
        }
    }
};