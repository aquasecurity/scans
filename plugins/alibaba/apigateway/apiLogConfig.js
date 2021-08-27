var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'API Log Config',
    category: 'APIGateway',
    description: 'Ensure that API Gateway APIs are configured to publish logs to Log Service.',
    more_info: 'Publishing logs to Log Service helps in debugging issues related to request execution or client access to your API.',
    link: 'https://www.alibabacloud.com/help/doc-detail/64818.htm',
    recommended_action: 'Configure Log Service for API Gateway',
    apis: ['ApiGateway:DescribeApis', 'ApiGateway:DescribeLogConfig'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        for (const region of regions.apigateway) {            
            const describeApis = helpers.addSource(cache, source, 
                ['apigateway', 'DescribeApis', region]);

            if (!describeApis) continue;
            
            if (describeApis.err || !describeApis.data) {
                helpers.addResult(results, 3,
                    'Unable to describe APIs: ' + helpers.addError(describeApis), region);
                continue;
            }

            if (!describeApis.data.length) {
                helpers.addResult(results, 0, 'No APIs found', region);
                break;
            }            
            
            const describeLogConfig = helpers.addSource(cache, source,
                ['apigateway', 'DescribeLogConfig', region]);

            if (!describeLogConfig || describeLogConfig.err || !describeLogConfig.data){
                helpers.addResult(results, 3,
                    'Unable to describe log config: ' + helpers.addError(describeLogConfig), region);
                continue;
            }
            
            let configEnabled = false;
            if (describeLogConfig.data.length && describeLogConfig.data.find(config => config.SlsLogStore)) configEnabled = true;
            
            const status = configEnabled ? 0 : 2;
            helpers.addResult(results, status,
                `APIs are ${configEnabled ? '' : 'not '}configured to publish logs to Log Service`, region);
        }               

        callback(null, results, source);
    }
};