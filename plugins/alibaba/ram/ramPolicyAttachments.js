var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'RAM Policy Attachments',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM policies are not attached to RAM users and are only attached to groups and roles.',
    more_info: 'Assigning RAM policies at the group or role level reduces the complexity of access management which in-turn can reduce the possibility of accidental access to users.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116815.htm',
    recommended_action: 'Ensure that RAM policies are not attached with RAM users.',
    apis: ['RAM:ListUsers', 'RAM:ListPoliciesForUser', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', region, 'data']);

        var listUsers = helpers.addSource(cache, source,
            ['ram', 'ListUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query RAM users' + helpers.addError(listUsers), region);
            return callback(null, results, source);
        }

        if (!listUsers.data.length) {
            helpers.addResult(results, 0, 'No RAM users found', region);
            return callback(null, results, source);
        }

        for (var user of listUsers.data) {
            if (!user.UserName) continue;

            let resource = helpers.createArn('ram', accountId, 'user', user.UserName);

            let listPoliciesForUser = helpers.addSource(cache, source,
                ['ram', 'ListPoliciesForUser', region, user.UserName]);

            if (!listPoliciesForUser || listPoliciesForUser.err || !listPoliciesForUser.data || !listPoliciesForUser.data.Policies) {
                helpers.addResult(results, 3,
                    `Unable to query user policies: ${listPoliciesForUser}`, region, resource);
                continue;
            }

            if (listPoliciesForUser.data.Policies.Policy && listPoliciesForUser.data.Policies.Policy.length) {
                helpers.addResult(results, 2,
                    `User has ${listPoliciesForUser.data.Policies.Policy.length} policy(s) attached`, region, resource);
            } else {
                helpers.addResult(results, 0,
                    'No policies are attached to user', region, resource);
            }
        }

        callback(null, results, source);
    }
};