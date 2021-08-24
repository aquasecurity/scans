var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Default Ports',
    category: 'ElastiCache',
    description: 'Ensure AWS ElastiCache clusters are not using the default ports set for Redis and Memcached cache engines.',
    more_info: 'ElastiCache clusters should not be using the default assigned port value.',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/accessing-elasticache.html',
    recommended_action: 'Configure ElastiCache clusters to use the non-default ports.',
    apis: ['ElastiCache:describeCacheClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultPorts = [
            { 'engine':'redis', 'port': 6379},
            { 'engine':'memcached', 'port': 11211},
        ];

        async.each(regions.elasticache, function(region, rcb){
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to describe cache clusters: ' + helpers.addError(describeCacheClusters), region);
                return rcb();
            }

            if (!describeCacheClusters.data.length) {
                helpers.addResult(results, 0, 'No cache clusters found', region);
                return rcb();
            }

            var found = false;

            for (var c in describeCacheClusters.data) {
                var cluster = describeCacheClusters.data[c];

                if (!cluster.Engine ||
                    !(cluster.ConfigurationEndpoint && cluster.ConfigurationEndpoint.Port)) continue;

                var defaultPort = defaultPorts.filter((d) => {
                    return d.engine == cluster.Engine && d.port == cluster.ConfigurationEndpoint.Port;
                });

                if (defaultPort && defaultPort.length>0){
                    found = true;

                    helpers.addResult(results, 2,
                        'The ' + cluster.Engine + ' cluster is configured with default port ' + cluster.ConfigurationEndpoint.Port,
                        region, cluster.CacheClusterId);
                }
            }

            if (!found) {
                helpers.addResult(results, 0,
                    'No clusters using default ports',
                    region);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
