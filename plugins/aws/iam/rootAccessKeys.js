var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Root Access Keys',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures the root account is not using access keys',
    more_info: 'The root account should avoid using access keys. Since the root account has full permissions across the entire account, creating access keys for it only increases the chance that they are compromised. Instead, create IAM users with predefined roles.',
    link: 'http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html',
    recommended_action: 'Remove access keys for the root account and setup IAM users with limited permissions instead',
    apis: ['IAM:generateCredentialReport'],
    compliance: {
        hipaa: 'HIPAA requires strong auditing controls surrounding actions ' +
                'taken in the environment. The root user lacks these controls ' +
                'since it is not tied to a specific user. The root access keys ' +
                'should not be used.',
        cis1: '1.12 Ensure no root account access key exists'
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

                if (!obj.access_key_1_active &&
                    !obj.access_key_2_active) {
                    helpers.addResult(results, 0, 'Access keys were not found for the root account', 'global', obj.arn);
                } else {
                    helpers.addResult(results, 2, 'Access keys were found for the root account', 'global', obj.arn);
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