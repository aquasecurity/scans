var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cluster Least Privilege',
    category: 'Kubernetes',
    domain: 'Containers',
    description: 'Ensures Kubernetes clusters using default service account are using minimal service account access scopes',
    more_info: 'As a best practice, Kubernetes clusters should not be created with default service account. But if they are, ' +
        'Kubernetes default service account should be limited to minimal access scopes necessary to operate the clusters.',
    link: 'https://cloud.google.com/compute/docs/access/service-accounts',
    recommended_action: 'Ensure that all Kubernetes clusters are created with minimal access scope.',
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

            const minimalAccess = [
                'https://www.googleapis.com/auth/devstorage.read_only',
                'https://www.googleapis.com/auth/logging.write',
                'https://www.googleapis.com/auth/monitoring',
                'https://www.googleapis.com/auth/servicecontrol',
                'https://www.googleapis.com/auth/service.management.readonly',
                'https://www.googleapis.com/auth/trace.append'
            ];

            clusters.data.forEach(cluster => {
                let location;
                if (cluster.locations) {
                    location = cluster.locations.length === 1 ? cluster.locations[0] : cluster.locations[0].substring(0, cluster.locations[0].length - 2);
                } else location = region;

                let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);

                let otherScope = false;
                if (cluster.nodeConfig &&
                    cluster.nodeConfig.serviceAccount &&
                    cluster.nodeConfig.serviceAccount == 'default') {
                    cluster.nodeConfig.oauthScopes.forEach((oneScope) => {
                        if (!minimalAccess.includes(oneScope)) otherScope = true;
                    });
                }

                if (otherScope) {
                    helpers.addResult(results, 2, 'No minimal access is allowed on Kubernetes cluster', region, resource);
                } else {
                    helpers.addResult(results, 0, 'Minimal access is allowed on Kubernetes cluster', region, resource);
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
}; 
