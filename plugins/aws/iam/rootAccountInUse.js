var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Root Account In Use',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures the root account is not being actively used',
    more_info: 'The root account should not be used for day-to-day account management. IAM users, roles, and groups should be used instead.',
    link: 'http://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html',
    recommended_action: 'Create IAM users with appropriate group-level permissions for account access. Create an MFA token for the root account, and store its password and token generation QR codes in a secure place.',
    apis: ['IAM:generateCredentialReport'],
    compliance: {
        hipaa: 'HIPAA requires strong auditing controls surrounding actions ' +
                'taken in the environment. The root user lacks these controls ' +
                'since it is not tied to a specific user. The root account ' +
                'should not be used.',
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. Restricting root access prevents access ' +
             'to these environments from users who may not be identified.',
        cis1: '1.1 Avoid the use of the root account'
    },
    settings: {
        root_account_in_use_days: {
            name: 'Root Account In Use Days',
            description: 'Return a failing result when the root account has been used within this many days',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 15
        }
    },

    run: function(cache, settings, callback) {
        this._run(cache, settings, callback, new Date());
    },

    _run: function(cache, settings, callback, now) {
        var config = {
            root_account_in_use_days: settings.root_account_in_use_days || this.settings.root_account_in_use_days.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var generateCredentialReport = helpers.addSource(cache, source,
            ['iam', 'generateCredentialReport', region]);

        if (!generateCredentialReport) return callback(null, results, source);

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3,
                'Unable to query for root user: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        var found = false;

        for (var r in generateCredentialReport.data) {
            var obj = generateCredentialReport.data[r];

            if (obj && obj.user === '<root_account>') {
                found = true;

                var accessDates = [];

                if (obj.password_last_used && obj.password_last_used !== 'N/A') {
                    accessDates.push(obj.password_last_used);
                }

                if (obj.access_key_1_last_used_date && obj.access_key_1_last_used_date !== 'N/A') {
                    accessDates.push(obj.access_key_1_last_used_date);
                }

                if (obj.access_key_2_last_used_date && obj.access_key_2_last_used_date !== 'N/A') {
                    accessDates.push(obj.access_key_2_last_used_date);
                }

                if (!accessDates.length) {
                    helpers.addResult(results, 0, 'Root account has not been used', 'global', obj.arn);
                } else {
                    var dateToCompare = helpers.mostRecentDate(accessDates);
                    var resultCode = (helpers.daysBetween(dateToCompare, now) < config.root_account_in_use_days) ? 2: 0;


                    helpers.addResult(results, resultCode,
                        'Root account was last used ' + helpers.daysBetween(dateToCompare, now) + ' days ago',
                        'global', obj.arn, custom);
                }

                break;
            }
        }

        if (!found) {
            helpers.addResult(results, 3, 'Unable to query for root user');
        }

        callback(null, results, source);

    }
};