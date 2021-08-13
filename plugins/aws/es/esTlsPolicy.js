var async = require('async');
var helpers = require('../../../helpers/aws');

var goodTlsPolicies = ['Policy-Min-TLS-1-2-2019-07'];

module.exports = {
    title: 'ElasticSearch TLS Policy',
    category: 'ES',
    description: 'Ensures ElasticSearch enables TLS 1.2 encryption',
    more_info: 'Its recommended for ElasticSearch domains to enable TLS 1.2 or later',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/infrastructure-security.html',
    recommended_action: 'Configure TLS 1.2 Policy for all ElasticSearch domains.',
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
                        goodTlsPolicies.indexOf(localDomain.DomainEndpointOptions.TLSSecurityPolicy) > -1) {
                        helpers.addResult(results, 0,
                            'ES domain is configured to use TLS 1.2 policy', region, localDomain.ARN);
                    } else {
                        helpers.addResult(results, 1,
                            'ES domain is not configured to use TLS 1.2 policy', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
