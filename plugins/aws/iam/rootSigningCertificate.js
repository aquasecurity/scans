var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Root Account Active Signing Certificates',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures the root user is not using x509 signing certificates',
    more_info: 'AWS supports using x509 signing certificates for API access, but these should not be attached to the root user, which has full access to the account.',
    link: 'https://docs.aws.amazon.com/whitepapers/latest/aws-overview-security-processes/x.509-certificates.html',
    recommended_action: 'Delete the x509 certificates associated with the root account.',
    apis: ['IAM:generateCredentialReport'],
    compliance: {
        hipaa: 'HIPAA requires strong auditing controls surrounding actions ' +
                'taken in the environment. The root user lacks these controls ' +
                'since it is not tied to a specific user. The root signing keys ' +
                'should not be used.'
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
            const resource = obj.arn;

            if (obj && obj.user && obj.user === '<root_account>') {
                found = true;

                if (obj.cert_1_active ||
                    obj.cert_2_active) {
                    helpers.addResult(results, 2, 'The root user uses x509 signing certificates.', 'global', resource);
                } else {
                    helpers.addResult(results, 0, 'The root user does not use x509 signing certificates.', 'global', resource);
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
