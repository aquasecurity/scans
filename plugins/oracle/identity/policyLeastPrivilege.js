var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Policy Least Privilege',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure only Compartment/Tenancy admins have blanket statements to manage or use resources without restriction.',
    more_info: 'Adding service-level admins to Oracle policies instead of blanket statements mitigates unintended access to resources by unauthorized users or groups.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/iam_security.htm',
    recommended_action: 'When writing policies, avoid blanket statements, and instead give full permissions only to Service-level admins, all other groups should have least access to services.',
    apis: ['policy:list'],
    compliance: {
        hipaa: 'MFA helps provide additional assurance that the user accessing ' +
            'the cloud environment has been identified. HIPAA requires ' +
            'strong controls around entity authentication which can be ' +
            'enhanced through the use of MFA.',
        pci: 'PCI requires MFA for all access to cardholder environments. ' +
            'Create an MFA key for user accounts.'
    },
    settings: {
        policy_group_admins: {
            name: 'Global Admins.',
            description: 'Comma separated list of all admins with permissions to use all resources to ignore for this plugin.',
            regex: '^.{1,255}$',
            default: 'Administrators'
        },
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var config = {
            policy_group_admins: settings.policy_group_admins || this.settings.policy_group_admins.default
        };

        var region = helpers.objectFirstKey(cache['regionSubscription']['list'])
        
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
        var policyProtection = true;
        var entered = false;
        var resourceTypes = ['all-resources'];
        policies.data.forEach(policy => {
            if (policy.statements &&
                policy.statements.length) {
                entered = true;
                policy.statements.forEach(statement => {
                    var statementObj = helpers.normalizePolicyStatement(statement);
                    var statementPasses = helpers.testStatement(statementObj, resourceTypes, config.policy_group_admins, ['manage', 'use']);

                    if (!statementPasses) {
                        policyProtection = false;

                        helpers.addResult(results, 2,
                            `${statementObj['subjectType']}${statementObj['subject']} has the ability to ${statementObj['verb']} all resources in ${statementObj['location']}`, region, policy.id);
                    }
                });
            }
        });

        if (policyProtection && entered) {
            helpers.addResult(results, 0, 'All policies follow least access.', region);
        }

        callback(null, results, source);
    }
};