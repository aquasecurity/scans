var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Root MFA Enabled',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures a multi-factor authentication device is enabled for the root account',
    more_info: 'The root account should have an MFA device setup to enable two-factor authentication.',
    link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
    recommended_action: 'Enable an MFA device for the root account and then use an IAM user for managing services',
    apis: ['IAM:generateCredentialReport'],
    compliance: {
        pci: 'PCI requires MFA for all access to cardholder environments. ' +
             'Create an MFA key for the root account and then lock it in ' +
             'a safe location for use as backup for named IAM users.',
        cis1: '1.13 Ensure MFA is enabled for the "root" account'
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
                'Unable to query for root user: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        var found = false;

        for (var r in generateCredentialReport.data) {
            var obj = generateCredentialReport.data[r];

            if (obj && obj.user === '<root_account>') {
                found = true;

                if (obj.mfa_active) {
                    helpers.addResult(results, 0,
                        'An MFA device was found for the root account', 'global', obj.arn);
                } else {
                    helpers.addResult(results, 2,
                        'An MFA device was not found for the root account', 'global', obj.arn);
                }

                break;
            }
        }

        if (settings.govcloud && !found) {
            helpers.addResult(results, 0, 'Root MFA is not required for AWS GovCloud');
        } else if (!found) {
            helpers.addResult(results, 3, 'Unable to query for root user');
        }

        callback(null, results, source);
    }
};