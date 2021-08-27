var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'API Group TLS Version',
    category: 'APIGateway',
    description: 'Ensure that API Gateway groups are using latest TLS version.',
    more_info: 'API Gateway groups should enforce TLS version 1.2.1 to ensure encryption of data in transit with updated features.',
    link: 'https://www.alibabacloud.com/help/doc-detail/115169.html',
    recommended_action: 'Configure latest TLS version for API Gateway groups',
    apis: ['ApiGateway:DescribeApiGroups', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        for (const region of regions.apigateway) {
            const describeApiGroups = helpers.addSource(cache, source,
                ['apigateway', 'DescribeApiGroups', region]);
                        
            if (!describeApiGroups) continue;

            if (describeApiGroups.err || !describeApiGroups.data){
                helpers.addResult(results, 3,
                    'Unable to describe APIs: ' + helpers.addError(describeApiGroups), region);
                continue;
            }

            if (!describeApiGroups.data.length) {
                helpers.addResult(results, 0, 'No API groups found', region);
                continue;
            }

            for (const apiGroup of describeApiGroups.data) {
                if (!apiGroup.GroupId) continue;

                var resource = helpers.createArn('apigateway', accountId, 'apigroup', apiGroup.GroupId, region);
                let configEnabled = false;
                if (apiGroup.HttpsPolicy && apiGroup.HttpsPolicy == 'HTTPS2_TLS1_2') configEnabled = true;
                
                const status = configEnabled ? 0 : 2;
                helpers.addResult(results, status,
                    `API instance ${configEnabled ? 'has' : 'does not have'} latest TLS version`, region, resource);
            }
        }
        callback(null, results, source);
    }
};