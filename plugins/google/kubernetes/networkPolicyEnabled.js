var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Network Policy Enabled',
    category: 'Kubernetes',
    domain: 'Containers',
    description: 'Ensures all Kubernetes clusters have network policy enabled',
    more_info: 'Kubernetes network policy creates isolation between cluster pods, this creates a more secure environment with only specified connections allowed.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy',
    recommended_action: 'Enable network policy on all Kubernetes clusters.',
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
                if (cluster.networkPolicy &&
                    cluster.networkPolicy.enabled) {
                    helpers.addResult(results, 0, 'Network policy is enabled for the Kubernetes cluster', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Network policy is disabled for the Kubernetes cluster', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}