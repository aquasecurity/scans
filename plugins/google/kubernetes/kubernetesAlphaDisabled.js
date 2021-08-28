var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Kubernetes Alpha Disabled',
    category: 'Kubernetes',
    domain: 'Containers',
    description: 'Ensure the GKE Cluster alpha cluster feature is disabled.',
    more_info: 'It is recommended to not use Alpha clusters as they expire after thirty days and do not receive security updates.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/concepts/alpha-clusters',
    recommended_action: '1. Create a new cluster with the alpha feature disabled. 2. Migrate all required cluster data from the cluster with alpha to this newly created cluster. 3.Delete the engine cluster with alpha enabled.',
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
                if (!cluster.name) return;
                let location;
                if (cluster.locations) {
                    location = cluster.locations.length === 1 ? cluster.locations[0] : cluster.locations[0].substring(0, cluster.locations[0].length - 2);
                } else location = region;

                let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);

                if (!cluster.enableKubernetesAlpha) {
                    helpers.addResult(results, 0,
                        'Kubernetes cluster has alpha feature disabled', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Kubernetes cluster does not have alpha feature disabled', region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};