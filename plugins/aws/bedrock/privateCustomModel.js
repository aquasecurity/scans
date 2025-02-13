var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Private Custom Model',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensure that an Amazon Bedrock custom model is configured within a private VPC.',
    more_info: 'When the custom model is configured within a private VPC or with a private VPC endpoint, it enhances security by restricting access to authorized networks only, preventing exposure to the public internet.',
    recommended_action: 'Configure the custom model with VPC and private VPC endpoint.',
    link: 'https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html',
    apis: ['Bedrock:listCustomModels', 'Bedrock:getCustomModel','Bedrock:listModelCustomizationJobs', 'Bedrock:getModelCustomizationJob','EC2:describeSubnets', 'EC2:describeRouteTables'],

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
            var subnetRouteTableMap;
            var privateSubnets = [];

            var describeSubnets = helpers.addSource(cache, source,
                ['ec2', 'describeSubnets', region]);
            var describeRouteTables = helpers.addSource(cache, {},
                ['ec2', 'describeRouteTables', region]);

            if (!describeRouteTables || describeRouteTables.err || !describeRouteTables.data ) {
                helpers.addResult(results, 3,
                    'Unable to query for route tables: ' + helpers.addError(describeRouteTables), region);
                return rcb();
            }     

            if (!describeSubnets || describeSubnets.err || !describeSubnets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for subnets: ' + helpers.addError(describeSubnets), region);
                return rcb();                  
            } else {
                subnetRouteTableMap = helpers.getSubnetRTMap(describeSubnets.data, describeRouteTables.data);
                privateSubnets = helpers.getPrivateSubnets(subnetRouteTableMap, describeSubnets.data, describeRouteTables.data);   
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

                if (getModelJob.data.vpcConfig && getModelJob.data.vpcConfig.subnetIds) { 
                    var allPrivate = getModelJob.data.vpcConfig.subnetIds.every(subnetId => privateSubnets.includes(subnetId));

                    if (allPrivate) {
                        helpers.addResult(results, 0,
                            'Bedrock custom model is configured within a private VPC',
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Bedrock custom model is not configured within a private VPC',
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Bedrock custom model does not have VPC configured',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
