var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Users MFA Enabled',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensures a multi-factor authentication device is enabled for all RAM users within the account',
    more_info: 'RAM User should have an MFA device setup to enable two-factor authentication.',
    link: 'https://partners-intl.aliyun.com/help/doc-detail/119555.htm',
    recommended_action: 'Enable an MFA device for the RAM users',
    apis: ['RAM:ListUsers', 'RAM:GetUserMFAInfo', 'STS:GetCallerIdentity'],
    compliance: {
        hipaa: 'MFA helps provide additional assurance that the user accessing ' +
                'the Alibaba environment has been identified. HIPAA requires ' +
                'strong controls around entity authentication which can be ' +
                'enhanced through the use of MFA.',
        pci: 'PCI requires MFA for all access to cardholder environments. ' +
             'Create an MFA key for RAM users.',
        cis: '1.4 Ensure that multi-factor authentication is enabled for all RAM users that have a console password'
    },

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

            var getUserMfa = helpers.addSource(cache, source,
                ['ram', 'GetUserMFAInfo', region, user.UserName]);

            var resource = helpers.createArn('ram', accountId, 'user', user.UserName);

            if (getUserMfa && getUserMfa.err && getUserMfa.err.code && getUserMfa.err.code === 'EntityNotExist.User.MFADevice') {
                helpers.addResult(results, 2,
                    'RAM user does not have MFA device configured', region, resource);
            } else if (!getUserMfa || getUserMfa.err || !getUserMfa.data) {
                helpers.addResult(results, 3,
                    'Unable to query RAM user MFA info', region, resource);
            } else {
                helpers.addResult(results, 0,
                    'RAM user has MFA device configured', region, resource);
            }
        }

        callback(null, results, source);
    }
};