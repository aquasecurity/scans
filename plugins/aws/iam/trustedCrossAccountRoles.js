var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Trusted Cross Account Roles',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures that only trusted cross-account IAM roles can be used.',
    more_info: 'IAM roles should be configured to allow access to trusted account IDs.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html',
    recommended_action: 'Delete the IAM roles that are associated with untrusted account IDs.',
    apis: ['IAM:listRoles', 'STS:getCallerIdentity', 'Organizations:listAccounts'],
    settings: {
        whitelisted_aws_account_principals: {
            name: 'Whitelisted AWS Account Principals',
            description: 'A comma-separated list of trusted cross account principals',
            regex: '^.*$',
            default: ''
        },
        whitelisted_aws_account_principals_regex: {
            name: 'Whitelisted AWS Account Principals Regex',
            description: 'If set, plugin will compare cross account principals against this regex instead of otherwise given comma-separated list' +
                'Example regex: ^arn:aws:iam::(111111111111|222222222222|):.+$',
            regex: '^.*$',
            default: ''
        },
        iam_whitelist_aws_organization_accounts: {
            name: 'Whitelist AWS Organization Accounts',
            description: 'If true, trust all accounts in current AWS organization',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var config= {
            whitelisted_aws_account_principals : settings.whitelisted_aws_account_principals || this.settings.whitelisted_aws_account_principals.default,
            whitelisted_aws_account_principals_regex : settings.whitelisted_aws_account_principals_regex || this.settings.whitelisted_aws_account_principals_regex.default,
            iam_whitelist_aws_organization_accounts: settings.iam_whitelist_aws_organization_accounts || this.settings.iam_whitelist_aws_organization_accounts.default
        };
        var makeRegexBased = (config.whitelisted_aws_account_principals_regex.length) ? true : false;
        var whitelistOrganization = (config.iam_whitelist_aws_organization_accounts == 'true'); 
        config.whitelisted_aws_account_principals_regex = new RegExp(config.whitelisted_aws_account_principals_regex);
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);

        var listRoles = helpers.addSource(cache, source,
            ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                `Unable to query for IAM roles: ${helpers.addError(listRoles)}`);
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }

        let organizationAccounts = [];
        if (whitelistOrganization) {
            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', region]);
    
            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, region);
                return callback(null, results, source);
            }

            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
        }

        listRoles.data.forEach(role => {
            if (!role.Arn || !role.AssumeRolePolicyDocument) return;

            var statements = helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument);

            if (!statements || !statements.length) {
                helpers.addResult(results, 0,
                    'IAM role does not contain trust relationship statements',
                    'global', role.Arn);
            }

            var restrictedAccountPrincipals = [];
            var crossAccountRole = false;

            for (var statement of statements) {
                if (!statement.Effect || statement.Effect !== 'Allow') continue;

                if (statement.Principal && helpers.crossAccountPrincipal(statement.Principal, accountId)) {
                    crossAccountRole = true;
                    var principals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
                    if (principals.length) {
                        principals.forEach(principal => {
                            if (whitelistOrganization) {
                                if (organizationAccounts.find(account => principal.includes(account))) return;
                            }
                            if (makeRegexBased) {
                                if (!config.whitelisted_aws_account_principals_regex.test(principal) &&
                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                            } else if (!config.whitelisted_aws_account_principals.includes(principal) &&
                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                        });
                    }
                }
            }

            if (crossAccountRole && !restrictedAccountPrincipals.length) {
                helpers.addResult(results, 0,
                    `Cross-account role "${role.RoleName}" contains trusted account principals only`,
                    'global', role.Arn);
            } else if (crossAccountRole) {
                helpers.addResult(results, 2,
                    `Cross-account role "${role.RoleName}" contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`,
                    'global', role.Arn);
            } else {
                helpers.addResult(results, 0,
                    `IAM Role "${role.RoleName}" does not contain cross-account statements`,
                    'global', role.Arn);
            }
        });
        
        callback(null, results, source);
    }
};