var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB Accelerator Cluster Encryption',
    category: 'DynamoDB',
    domain: 'Databases',
    description: 'Ensures DynamoDB Cluster Accelerator DAX clusters have encryption enabled.',
    more_info: 'DynamoDB Clusters Accelerator DAX clusters should have encryption at rest enabled to secure data from unauthorized access.',
    link: 'https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html',
    recommended_action: 'Enable encryption for DAX cluster.',
    apis: ['DAX:describeClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.dynamodb, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['dax', 'describeClusters', region]);

            if (!describeClusters) return rcb();
            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for DAX clusters: ' + helpers.addError(describeClusters), region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No DAX clusters found', region);
                return rcb();
            }

            for (var c in describeClusters.data) {
                var cluster = describeClusters.data[c];
                var resource = cluster.ClusterArn;

                if (cluster.SSEDescription &&
                    cluster.SSEDescription.Status &&
                    cluster.SSEDescription.Status.toUpperCase() === 'ENABLED') {
                    helpers.addResult(results, 0,
                        'Encryption is enabled for DAX :' + cluster.ClusterName, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Encryption is not enabled for DAX :' + cluster.ClusterName, region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
