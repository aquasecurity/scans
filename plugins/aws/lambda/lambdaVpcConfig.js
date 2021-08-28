var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda VPC Config',
    category: 'Lambda',
    domain: 'Serverless',
    description: 'Ensures Lambda functions are created in a VPC.',
    more_info: 'Lambda functions should be created in an AWS VPC to avoid exposure to the Internet and to enable communication with VPC resources through NACLs and security groups.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/vpc.html',
    recommended_action: 'Update the Lambda function with a VPC configuration.',
    apis: ['Lambda:listFunctions'],
    settings: {
        lambda_whitelist: {
            name: 'Lambda Functions Whitelisted',
            description: 'A comma-delimited list of known lambda function Function Names that should be whitelisted',
            regex: '^.{1,255}$',
            default: 'Aqua-CSPM-Token-Rotator-Function'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            lambda_whitelist: settings.lambda_whitelist || this.settings.lambda_whitelist.default
        };

        if (config.lambda_whitelist &&
            config.lambda_whitelist.length) {
            config.lambda_whitelist = config.lambda_whitelist.split(',');
        } else {
            config.lambda_whitelist = [];
        }

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            for (var f in listFunctions.data) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var lambdaFunction = listFunctions.data[f];

                if (config.lambda_whitelist.length &&
                    config.lambda_whitelist.indexOf(lambdaFunction.FunctionName)>-1) {
                    helpers.addResult(results, 0,
                        'The function ' + lambdaFunction.FunctionName + ' is whitelisted.',
                        region, lambdaFunction.FunctionArn);
                } else {
                    if (lambdaFunction.VpcConfig && lambdaFunction.VpcConfig.VpcId) {
                        helpers.addResult(results, 0,
                            'Function is being launched into a VPC',
                            region, lambdaFunction.FunctionArn);
                    } else {
                        helpers.addResult(results, 2,
                            'Function is not being launched into a VPC',
                            region, lambdaFunction.FunctionArn);
                    }
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
