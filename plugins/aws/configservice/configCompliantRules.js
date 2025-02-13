var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Config Compliant Rules',
    category: 'ConfigService',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that all the evaluation results returned from the Amazon Config rules created within your AWS account are compliant.',
    more_info: 'AWS Config provides AWS managed rules, which are predefined customizable rules that AWS Config uses to evaluate whether your AWS resources comply with common best practices.',
    recommended_action: 'Enable the AWS Config Service rules for compliance checks and close security gaps.',
    link: 'https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html',
    apis: ['ConfigService:describeConfigRules', 'ConfigService:getComplianceDetailsByConfigRule'],
    realtime_triggers: ['configservice:PutConfigurationRecorder','configservice:PutConfigRule','configservice:DeleteConfigRule'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.configservice, function(region, rcb){        
            var describeConfigRules = helpers.addSource(cache, source,
                ['configservice', 'describeConfigRules', region]);           

            if (!describeConfigRules) return rcb();

            if (describeConfigRules.err || !describeConfigRules.data) {
                helpers.addResult(results, 3,
                    'Unable to query Config Rules: ' + helpers.addError(describeConfigRules), region);
                return rcb();
            }

            if (!describeConfigRules.data.length) {
                helpers.addResult(results, 0, 'No Config Rules found', region);
                return rcb();
            }
            
            for (let rule of describeConfigRules.data) {
                if (!rule.ConfigRuleArn) continue;
               
                let resource = rule.ConfigRuleArn;
                var getComplianceDetailsByConfigRule = helpers.addSource(cache, source,
                    ['configservice', 'getComplianceDetailsByConfigRule', region, rule.ConfigRuleName]);
                
                if (!getComplianceDetailsByConfigRule || getComplianceDetailsByConfigRule.err || !getComplianceDetailsByConfigRule.data) {
                    helpers.addResult(results, 3,
                        `Unable to get Evaluation Results: ${helpers.addError(getComplianceDetailsByConfigRule)}`,
                        region, resource);
                    continue;
                }

                if (!getComplianceDetailsByConfigRule.data.EvaluationResults ||
                    !getComplianceDetailsByConfigRule.data.EvaluationResults.length){
                    helpers.addResult(results, 0, 'Amazon Config rule returns compliant evaluation results',
                        region, resource);
                } else {
                    helpers.addResult(results, 2, 'Amazon Config rule returns noncompliant evaluation results',
                        region, resource);
                }
            }

            rcb();  
        }, function(){
            callback(null, results, source);
        });
    }
};
