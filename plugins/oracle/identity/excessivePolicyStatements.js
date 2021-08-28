var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Excessive Policy Statements',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Determine if there are an excessive number of policy statements in the account',
    more_info: 'Keeping the number of policy statements to a minimum helps reduce the chances ' +
        'of compromised accounts causing catastrophic damage to the account. Common statements ' +
        'should be grouped under the same policy. ',
    recommended_action: 'Limit the number of policy statements to prevent accidental authorizations',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/policygetstarted.htm',
    apis: ['policy:list'],
    
    settings: {
        excessive_policy_statement_fail: {
            name: 'Excessive Policy Statements Fail',
            description: 'Return a failing result when the number of Policy Statements exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 25
        },
        excessive_policy_statement_warn: {
            name: 'Excessive Policy Statements Warn',
            description: 'Return a warning result when the number of Policy Statements exceeds this value',
            regex: '^[1-9]{1}[0-9]{0,5}$',
            default: 15
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var config = {
            excessive_policy_statement_fail: settings.excessive_policy_statement_fail || this.settings.excessive_policy_statement_fail.default,
            excessive_policy_statement_warn: settings.excessive_policy_statement_warn || this.settings.excessive_policy_statement_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);
        
        var region = helpers.objectFirstKey(cache['regionSubscription']['list'])
        

        if (helpers.checkRegionSubscription(cache, source, results, region)) {

            var policies = helpers.addSource(cache, source,
                ['policy', 'list', region]);

            if (!policies) return callback(null, results, source);

            if (policies.err || !policies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for policies: ' + helpers.addError(policies), region);
                return callback(null, results, source);
            }

            if (!policies.data.length) {
                helpers.addResult(results, 0, 'No policies found', region);
                return callback(null, results, source);
            }

            policies.data.forEach(policy => {
                var policyAmt = policy.statements.length;
                var returnMsg = ' number of policy statements: ' + policyAmt + ' found';

                if (policyAmt > config.excessive_policy_statement_fail) {
                    helpers.addResult(results, 2, 'Excessive' + returnMsg, region, policy.id, custom);
                } else if (policyAmt > config.excessive_policy_statement_warn) {
                    helpers.addResult(results, 1, 'Large' + returnMsg, region, policy.id, custom);
                } else {
                    helpers.addResult(results, 0, 'Acceptable' + returnMsg, region, policy.id, custom);
                }
            });
        }

        callback(null, results, source);
    }
};