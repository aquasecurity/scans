var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cross-Account Access External ID and MFA',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures that either MFA or external IDs are used to access AWS roles.',
    more_info: 'IAM roles should be configured to require either a shared external ID or use an MFA device when assuming the role.',
    link: 'https://aws.amazon.com/blogs/aws/mfa-protection-for-cross-account-access/',
    recommended_action: 'Update the IAM role to either require MFA or use an external ID.',
    apis: ['IAM:listRoles', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', region, 'data']);

        var listRoles = helpers.addSource(cache, source,
            ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM roles: ' + helpers.addError(listRoles));
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }

        listRoles.data.forEach(role => {
            if (!role.AssumeRolePolicyDocument || !role.Arn) {
                return;
            }

            var resource = role.Arn;

            var statements = helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument);

            if (!statements || !statements.length) {
                helpers.addResult(results, 0,
                    'IAM role does not contain trust relationship statements',
                    'global', resource);
                return;
            }

            var failingArns = [];
            var crossAccountRole = false;
            
            for (var s in statements) {
                var statement = statements[s];

                if (statement.Principal && helpers.crossAccountPrincipal(statement.Principal, accountId)) {
                    crossAccountRole = true;

                    if (!((statement.Condition && statement.Condition.Bool &&
                            statement.Condition.Bool['aws:MultiFactorAuthPresent'] &&
                            statement.Condition.Bool['aws:MultiFactorAuthPresent'] === 'true') ||
                            (statement.Condition && statement.Condition.StringEquals &&
                                statement.Condition.StringEquals['sts:ExternalId']))) {
                        var principals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
                        if (principals.length) {
                            principals.forEach(principal => {
                                if (!failingArns.includes(principal)) failingArns.push(principal);
                            });
                        }
                    }
                }
            }

            if (crossAccountRole && failingArns.length) {
                helpers.addResult(results, 2,
                    'Cross-account role does not require MFA/external ID for these account ARNs: ' + failingArns.join(', '),
                    'global', resource);
            } else if (crossAccountRole) {
                helpers.addResult(results, 0,
                    'Cross-account role requires MFA/external ID for all accounts',
                    'global', resource);
            } else {
                helpers.addResult(results, 0,
                    'IAM role does not contain cross-account statements',
                    'global', resource);
            }
        });
        
        callback(null, results, source);
    }
};