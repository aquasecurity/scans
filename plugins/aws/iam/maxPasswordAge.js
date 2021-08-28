var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Maximum Password Age',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures password policy requires passwords to be reset every 180 days',
    more_info: 'A strong password policy enforces minimum length, expirations, reuse, and symbol usage',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Descrease the maximum allowed age of passwords for the password policy',
    apis: ['IAM:getAccountPasswordPolicy'],
    remediation_description: 'The password policy for maximum password age will be set to the value set by the user. Otherwise, it will default to 179.',
    remediation_min_version: '202006221808',
    apis_remediate: ['IAM:getAccountPasswordPolicy'],
    remediation_inputs: {
        maxPasswordAge: {
            name: '(Optional) Maximum Password Age',
            description: 'The maximum age of passwords to allow in the account policy 1-1095',
            regex: '^([1-9][0-9]{0,2}|10[0-9][0-5])$',
            required: false
        },
        maxPasswordAgeCreatePolicy: {
            name: 'Create Password Policy',
            description: 'Whether to create a new password policy if one does not already exist.',
            regex: '^(true|false)$',
            required: false
        }
    },
    actions: {remediate: ['IAM:updateAccountPasswordPolicy'], rollback: ['IAM:updateAccountPasswordPolicy']},
    permissions: {remediate: ['iam:UpdateAccountPasswordPolicy'], rollback: ['iam:UpdateAccountPasswordPolicy']},
    compliance: {
        pci: 'PCI requires that all user credentials are rotated every 90 days. Setting ' +
             'an IAM password rotation policy enforces this requirement.'
    },
    settings: {
        max_password_age_fail: {
            name: 'Max Password Age Fail',
            description: 'Return a failing result when max password age exceeds this number of days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 365
        },
        max_password_age_warn: {
            name: 'Max Password Age Warn',
            description: 'Return a warning result when max password age exceeds this number of days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 180
        }
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
        var config = {
            max_password_age_fail: settings.max_password_age_fail || this.settings.max_password_age_fail.default,
            max_password_age_warn: settings.max_password_age_warn || this.settings.max_password_age_warn.default
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

        if (!passwordPolicy.MaxPasswordAge) {
            helpers.addResult(results, 2, 'Password policy does not specify a maximum password age');
        } else if (passwordPolicy.MaxPasswordAge > config.max_password_age_fail) {
            helpers.addResult(results, 2, 'Maximum password age of: ' + passwordPolicy.MaxPasswordAge + ' days is more than one year', 'global', null, custom);
        } else if (passwordPolicy.MaxPasswordAge > config.max_password_age_warn) {
            helpers.addResult(results, 1, 'Maximum password age of: ' + passwordPolicy.MaxPasswordAge + ' days is more than six months', 'global', null, custom);
        } else {
            helpers.addResult(results, 0, 'Maximum password age of: ' + passwordPolicy.MaxPasswordAge + ' days is suitable', 'global', null, custom);
        }

        callback(null, results, source);
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;
        var pluginName = 'maxPasswordAge';
        var passwordKey = 'MaxPasswordAge';
        var input = {};
        if (settings.input && settings.input['maxPasswordAge']) {
            input[passwordKey] = `${settings.input['maxPasswordAge']}`;
        } else {
            input[passwordKey] = '179';
        }


        helpers.remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback);
    }
};