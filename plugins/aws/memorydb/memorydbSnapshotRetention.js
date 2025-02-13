var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'MemoryDB Cluster Automated Snapshot Retention Period',
    category: 'MemoryDB',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that retention period is set for Amazon MemoryDB cluster automated snapshots.',
    more_info: 'MemoryDB clusters should have retention period set for automated snapshots for data protection and to avoid unexpected failures.',
    recommended_action: 'Modify MemoryDB cluster and enable automatic snapshots',
    link: 'https://docs.aws.amazon.com/memorydb/latest/devguide/snapshots-automatic.html',
    apis: ['MemoryDB:describeClusters'],
    realtime_triggers: ['MemoryDB:CreateCluster', 'MemoryDB:DeleteCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.memorydb, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['memorydb', 'describeClusters', region]);
                
            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list MemoryDB clusters: ${helpers.addError(describeClusters)}`, region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0,
                    'No MemoryDB clusters found', region);
                return rcb();
            }

            for (let cluster of describeClusters.data) {
                if (!cluster.ARN) continue;

                let resource = cluster.ARN;

                if (cluster.SnapshotRetentionLimit && cluster.SnapshotRetentionLimit > 0) {
                    
                    helpers.addResult(results, 0, 'MemoryDB cluster has snapshot retention period set', region, resource);
                } else {
                    helpers.addResult(results, 2, 'MemoryDB cluster does not have snapshot retention period set', region, resource);
                }  
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};