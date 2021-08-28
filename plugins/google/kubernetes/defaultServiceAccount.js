var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Default Service Account',
    category: 'Kubernetes',
    domain: 'Containers',
    description: 'Ensures all Kubernetes cluster nodes are not using the default service account.',
    more_info: 'Kubernetes cluster nodes should use customized service accounts that have minimal privileges to run. This reduces the attack surface in the case of a malicious attack on the cluster.',
    link: 'https://cloud.google.com/container-optimized-os/',
    recommended_action: 'Ensure that no Kubernetes cluster nodes are using the default service account',
    apis: ['clusters:list', 'projects:get'],

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

        async.each(regions.clusters, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Kubernetes clusters', region, null, null, clusters.err);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                let location;
                if (cluster.locations) {
                    location = cluster.locations.length === 1 ? cluster.locations[0] : cluster.locations[0].substring(0, cluster.locations[0].length - 2);
                } else location = region;

                let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);

                let found = false;
                let defaultSaNodes = [];
                if (cluster.nodePools &&
                    cluster.nodePools.length) {
                    cluster.nodePools.forEach(nodePool => {
                        found = true;
                        if (nodePool.config &&
                            nodePool.config.serviceAccount &&
                            nodePool.config.serviceAccount === "default") defaultSaNodes.push(nodePool.name);
                    });
                }

                if (defaultSaNodes.length) {
                    helpers.addResult(results, 2,
                        `The default service account is being used for these node pools: ${cluster.name}`, region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'The default service account is not being used for the node pools', region, resource);
                }
                
                if (!found) {
                    helpers.addResult(results, 0, 'No node pools found', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};