var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Private Cluster Enabled',
    category: 'Kubernetes',
    domain: 'Containers',
    description: 'Ensures private cluster is enabled for all Kubernetes clusters',
    more_info: 'Kubernetes private clusters only have internal ip ranges, which ensures that their workloads are isolated from the public internet.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters',
    recommended_action: 'Ensure that all Kubernetes clusters have private cluster enabled.',
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

        async.each(regions.clusters, (region, rcb) => {
            var clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query Kubernetes clusters', region, null, null, clusters.err);
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

                if (cluster.privateCluster) {
                    helpers.addResult(results, 0, 'Private cluster is enabled on the Kubernetes cluster', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Private cluster is disabled on the Kubernetes cluster', region, resource);
                }

            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};