var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch HTTPS Only',
    category: 'ES',
    description: 'Ensures ElasticSearch domains are configured to enforce HTTPS connections',
    more_info: 'ElasticSearch domains should be configured to enforce HTTPS connections for all clients to ensure encryption of data in transit.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html',
    recommended_action: 'Ensure HTTPS connections are enforced for all ElasticSearch domains.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.es, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for ES domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region);
                } else {
                    var localDomain = describeElasticsearchDomain.data.DomainStatus;

                    if (localDomain.DomainEndpointOptions &&
                        localDomain.DomainEndpointOptions.EnforceHTTPS) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to enforce HTTPS', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain is not configured to enforce HTTPS', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
