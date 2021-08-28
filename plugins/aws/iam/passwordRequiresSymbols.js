var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Password Requires Symbols',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures password policy requires the use of symbols',
    more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Update the password policy to require the use of symbols',
    apis: ['IAM:getAccountPasswordPolicy'],
    remediation_description: 'The password policy for password requires symbols will be set to true.',
    remediation_min_version: '202006221808',
    apis_remediate: ['IAM:getAccountPasswordPolicy'],
    remediation_inputs: {
        passwordRequiresSymbolsCreatePolicy: {
            name: 'Create Password Policy',
            description: 'Whether to create a new password policy if one does not already exist.',
            regex: '^(true|false)$',
            required: false
        }
    },
    actions: {remediate: ['IAM:updateAccountPasswordPolicy'], rollback: ['IAM:updateAccountPasswordPolicy']},
    permissions: {remediate: ['iam:UpdateAccountPasswordPolicy'], rollback: ['iam:UpdateAccountPasswordPolicy']},
    compliance: {
        pci: 'PCI requires a strong password policy. Setting IAM password ' +
             'requirements enforces this policy.',
        cis1: '1.7 Ensure IAM password policy require at least one symbol'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var getAccountPasswordPolicy = helpers.addSource(cache, source,
            ['iam', 'getAccountPasswordPolicy', region]);

        if (!getAccountPasswordPolicy) return callback(null, results, source);

        // Handle special case errors
        if (getAccountPasswordPolicy.err &&
            getAccountPasswordPolicy.err.code &&
            getAccountPasswordPolicy.err.code === 'NoSuchEntity') {
            helpers.addResult(results, 2, 'Account does not have a password policy');
            return callback(null, results, source);
        }

        if (getAccountPasswordPolicy.err || !getAccountPasswordPolicy.data) {
            helpers.addResult(results, 3,
                'Unable to query for password policy status: ' + helpers.addError(getAccountPasswordPolicy));
            return callback(null, results, source);
        }

        var passwordPolicy = getAccountPasswordPolicy.data;

        if (!passwordPolicy.RequireSymbols) {
            helpers.addResult(results, 1, 'Password policy does not require symbols');
        } else {
            helpers.addResult(results, 0, 'Password policy requires symbols');
        }

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'passwordRequiresSymbols';
        var passwordKey = 'RequireSymbols';
        var input = {};
        input[passwordKey] = true;

        helpers.remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback);
    }
};