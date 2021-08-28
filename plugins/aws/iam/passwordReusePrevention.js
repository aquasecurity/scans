var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Password Reuse Prevention',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures password policy prevents previous password reuse',
    more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Increase the minimum previous passwords that can be reused to 24.',
    apis: ['IAM:getAccountPasswordPolicy'],
    remediation_description: 'The password policy for password reuse prevention will be set to the value set by the user. Otherwise, it will default to 24.',
    remediation_min_version: '202006221808',
    apis_remediate: ['IAM:getAccountPasswordPolicy'],
    remediation_inputs: {
        maxPreviousPasswords: {
            name: '(Optional) Minimum Previous Passwords',
            description: 'The minimum number of previous passwords to allow in the account policy 1-24',
            regex: '^([1-9]|[0-1][0-9]|2[0-4])$',
            required: false
        },
        passwordReusePreventionCreatePolicy: {
            name: 'Create Password Policy',
            description: 'Whether to create a new password policy if one does not already exist.',
            regex: '^(true|false)$',
            required: false
        }
    },
    actions: {remediate: ['IAM:updateAccountPasswordPolicy'], rollback: ['IAM:updateAccountPasswordPolicy']},
    permissions: {remediate: ['iam:UpdateAccountPasswordPolicy'], rollback: ['iam:UpdateAccountPasswordPolicy']},
    compliance: {
        pci: 'PCI requires that the previous 4 passwords not be reused. ' +
             'Restricting IAM password reuse enforces this policy.',
        cis1: '1.10 Ensure IAM password policy prevents password reuse'
    },
    settings: {
        password_reuse_fail: {
            name: 'Password Reuse Fail',
            description: 'Return a failing result when password reuse policy remembers fewer than this many past passwords',
            regex: '^[1-9]{1}[0-9]{0,2}$',
            default: 5
        },
        password_reuse_warn: {
            name: 'Password Reuse Warn',
            description: 'Return a warning result when password reuse policy remembers fewer than this many past passwords',
            regex: '^[1-9]{1}[0-9]{0,2}$',
            default: 24
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            password_reuse_fail: settings.password_reuse_fail || this.settings.password_reuse_fail.default,
            password_reuse_warn: settings.password_reuse_warn || this.settings.password_reuse_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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

        if (!passwordPolicy.PasswordReusePrevention) {
            helpers.addResult(results, 2, 'Password policy does not prevent reusing previous passwords');
        } else if (passwordPolicy.PasswordReusePrevention < config.password_reuse_fail) {
            helpers.addResult(results, 2,
                'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than ' + config.password_reuse_fail, 'global', null, custom);
        } else if (passwordPolicy.PasswordReusePrevention < config.password_reuse_warn) {
            helpers.addResult(results, 1,
                'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is less than ' + config.password_reuse_warn, 'global', null, custom);
        } else {
            helpers.addResult(results, 0,
                'Maximum password reuse of: ' + passwordPolicy.PasswordReusePrevention + ' passwords is suitable', 'global', null, custom);
        }

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'passwordReusePrevention';
        var passwordKey = 'PasswordReusePrevention';

        var input = {};
        if (settings.input && settings.input['maxPreviousPasswords']) {
            input[passwordKey] = `${settings.input['maxPreviousPasswords']}`;
        } else {
            input[passwordKey] = '24';
        }

        helpers.remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback);
    }
};