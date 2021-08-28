var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Password Expiration',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures password policy enforces a password expiration',
    more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Enable password expiration for the account',
    apis: ['IAM:getAccountPasswordPolicy'],
    remediation_description: 'The password policy for password expiration will be set to true.',
    remediation_min_version: '202006221808',
    apis_remediate: ['IAM:getAccountPasswordPolicy'],
    remediation_inputs: {
        passwordExpirationCreatePolicy: {
            name: 'Create Password Policy',
            description: 'Whether to create a new password policy if one does not already exist.',
            regex: '^(true|false)$',
            required: false
        }
    },
    actions: {remediate: ['IAM:updateAccountPasswordPolicy'], rollback: ['IAM:updateAccountPasswordPolicy']},
    permissions: {remediate: ['iam:UpdateAccountPasswordPolicy'], rollback: ['iam:UpdateAccountPasswordPolicy']},
    compliance: {
        pci: 'PCI requires that user passwords are rotated every 90 days. Forcing ' +
             'password expirations enforces this policy.',
        cis1: '1.11 Ensure IAM password policy expires passwords within 90 days or less'
    },
    asl: {
        conditions: [
            {
                service: 'iam',
                api: 'getAccountPasswordPolicy',
                property: 'MaxPasswordAge',
                transform: 'INTEGER',
                op: 'GT',
                value: 90
            }
        ]
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

        if (!passwordPolicy.ExpirePasswords) {
            helpers.addResult(results, 2, 'Password expiration policy is not set to expire passwords');
            return callback(null, results, source);
        }

        var returnMsg = 'Password expiration of: ' + passwordPolicy.MaxPasswordAge + ' days is ';

        if (passwordPolicy.MaxPasswordAge > 180) {
            helpers.addResult(results, 2, returnMsg + 'greater than 180');
        } else if (passwordPolicy.MaxPasswordAge > 90) {
            helpers.addResult(results, 1, returnMsg + 'greater than 90');
        } else {
            helpers.addResult(results, 0, returnMsg + 'suitable');
        }

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'passwordExpiration';
        var passwordKey = 'HardExpiry';
        var input = {};
        input[passwordKey] = true;

        helpers.remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback);
    }
};