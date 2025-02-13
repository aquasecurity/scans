var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Custom Model In VPC',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensure that an Amazon Bedrock custom model is configured with a VPC.',
    more_info: 'When the custom model is configured within a VPC, it establishes a secure environment that prevents unauthorized internet access to your training data, enhancing the overall security and confidentiality of your model.',
    recommended_action: 'Create the custom model with VPC configuration',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/usingVPC.html',
    apis: ['Bedrock:listCustomModels', 'Bedrock:getCustomModel','Bedrock:listModelCustomizationJobs', 'Bedrock:getModelCustomizationJob'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.bedrock, function(region, rcb){
            var listCustomModels = helpers.addSource(cache, source,
                ['bedrock', 'listCustomModels', region]);

            if (!listCustomModels) return rcb();

            if (listCustomModels.err && listCustomModels.err.message.includes('Unknown operation')) {
                helpers.addResult(results, 0,
                    'Custom model service is not available in this region', region);
                return rcb();
            }

            if (listCustomModels.err || !listCustomModels.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Bedrock custom model list: ${helpers.addError(listCustomModels)}`, region);
                return rcb();
            }

            if (!listCustomModels.data.length) {
                helpers.addResult(results, 0, 'No Bedrock custom model found', region);
                return rcb();
            }

            for (let model of listCustomModels.data){
                if (!model.modelArn|| !model.modelName) continue;

                let resource = model.modelArn;

                let getCustomModel = helpers.addSource(cache, source,
                    ['bedrock', 'getCustomModel', region, model.modelName]);


                if (!getCustomModel || getCustomModel.err || !getCustomModel.data) {
                    helpers.addResult(results, 3, `Unable to describe Bedrock custom model : ${helpers.addError(getCustomModel)}`, region, resource);
                    continue;
                }

                let getModelJob = helpers.addSource(cache, source,
                    ['bedrock', 'getModelCustomizationJob', region, getCustomModel.data.jobArn]);

                if (!getModelJob || getModelJob.err || !getModelJob.data) {
                    helpers.addResult(results, 3, `Unable to describe Bedrock model customzation job : ${helpers.addError(getModelJob)}`, region, resource);
                    continue;
                }

                if (getModelJob.data.vpcConfig ) {
                    helpers.addResult(results, 0,
                        'Bedrock custom model is configured within a VPC', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Bedrock custom model is not configured within a VPC', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};