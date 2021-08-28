var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Environment Variables Client Side Encryption',
    category: 'Lambda',
    domain: 'Serverless',
    description: 'Ensure that all sensitive AWS Lambda environment variable values are client side encrypted.',
    more_info: 'AWS Lambda lets you encrypt environment variable values prior to sending them to Lambda. ' +
        'Environment variables are often used to store sensitive information such as passwords. Such variable valuesshould be ' +
        'encrypted for security best practices.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html',
    recommended_action: 'Encrypt environment variables that store sensitive information',
    apis: ['Lambda:listFunctions'],
    settings: {
        lambda_sensitive_env_vars: {
            name: 'Lambda Sensitive Environment Varibales',
            description: 'A comma-delimited list of known lambda function Environment Variables that should be encrypted',
            regex: '^.{1,255}$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            lambda_sensitive_env_vars: settings.lambda_sensitive_env_vars || this.settings.lambda_sensitive_env_vars.default
        };

        if (!config.lambda_sensitive_env_vars.length) return callback(null, results, source);

        config.lambda_sensitive_env_vars = config.lambda_sensitive_env_vars.split(',');

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Lambda functions: ${helpers.addError(listFunctions)}`, region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            for (var lambdaFunc of listFunctions.data) {
                if (!lambdaFunc.FunctionArn) continue;
                var resource = lambdaFunc.FunctionArn;

                if (!lambdaFunc.Environment || !lambdaFunc.Environment.Variables) {
                    helpers.addResult(results, 0,
                        'No environment variables found', region, resource);
                    continue;
                }

                var unencryptedVars = [];
                var encryptedVars = [];
                for (var envVar of config.lambda_sensitive_env_vars) {
                    if (lambdaFunc.Environment.Variables[envVar]) {
                        if (lambdaFunc.Environment.Variables[envVar].length !== 216) unencryptedVars.push(envVar);
                        else encryptedVars.push(envVar);
                    }
                }

                if (unencryptedVars.length) {
                    helpers.addResult(results, 2,
                        `Encryption not enabled for these sensitive environment variable values: ${unencryptedVars}`,
                        region, resource);
                } else if (encryptedVars.length){
                    helpers.addResult(results, 0,
                        'Encryption is enabled for sensitive environment variable values',
                        region, resource);
                } else {
                    helpers.addResult(results, 0, 'No sensitive environment variables found', region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
