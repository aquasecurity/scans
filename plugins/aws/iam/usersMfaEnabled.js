var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Users MFA Enabled',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures a multi-factor authentication device is enabled for all users within the account',
    more_info: 'User accounts should have an MFA device setup to enable two-factor authentication',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html',
    recommended_action: 'Enable an MFA device for the user account',
    apis: ['IAM:generateCredentialReport'],
    compliance: {
        hipaa: 'MFA helps provide additional assurance that the user accessing ' +
                'the AWS is environment has been identified. HIPAA requires ' +
                'strong controls around entity authentication which can be ' +
                'enhanced through the use of MFA.',
        pci: 'PCI requires MFA for all access to cardholder environments. ' +
             'Create an MFA key for user accounts.',
        cis1: '1.2 Ensure multi-factor authentication (MFA) is enabled for all ' +
              'IAM users that have a console password'
    },
    asl: {
        conditions: [
            {
                service: 'iam',
                api: 'generateCredentialReport',
                property: 'mfa_active',
                transform: 'STRING',
                op: 'EQ',
                value: 'true'
            }
        ]
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);

        var generateCredentialReport = helpers.addSource(cache, source,
            ['iam', 'generateCredentialReport', region]);

        if (!generateCredentialReport) return callback(null, results, source);

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3,
                'Unable to query for user MFA status: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        if (generateCredentialReport.data.length === 1) {
            // Only have the root user
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }

        var found = false;

        for (var r in generateCredentialReport.data) {
            var obj = generateCredentialReport.data[r];

            // Skip root user and users without passwords
            // since they won't be logging into the console
            if (obj.user === '<root_account>') continue;
            if (!obj.password_enabled) continue;

            found = true;

            if (obj.mfa_active) {
                helpers.addResult(results, 0,
                    'User: ' + obj.user + ' has an MFA device', 'global', obj.arn);
            } else {
                helpers.addResult(results, 2,
                    'User: ' + obj.user + ' does not have an MFA device enabled', 'global', obj.arn);
            }
        }

        if (!found) {
            helpers.addResult(results, 0, 'No users with passwords requiring MFA found');
        }

        callback(null, results, source);
    }
};