var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Inactive User Disabled',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM users inactive for 90 or more days are disabled.',
    more_info: 'RAM User should not have the console access enabled on being inactive for 90 or more days.',
    link: 'https://alibaba-cloud.medium.com/11-security-recommendations-for-production-instances-on-alibaba-cloud-960e3e8442d4',
    recommended_action: 'Disable RAM user if its inactive for 90 or more days',
    apis: ['RAM:ListUsers', 'RAM:GetUser', 'RAM:GetLoginProfile', 'STS:GetCallerIdentity'],

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
            
            var getUser = helpers.addSource(cache, source,
                ['ram', 'GetUser', region, user.UserName]);
            
            if (getUser.err || !getUser.data) {
                helpers.addResult(results, 3,
                    'Unable to query RAM user' + helpers.addError(getUser), region);
                continue;
            }

            let lastLoginDate = (getUser.data.LastLoginDate && getUser.data.LastLoginDate.length) ?
                getUser.data.LastLoginDate : getUser.data.CreateDate ;
            var currentDate = new Date();
            var loginDate = new Date(lastLoginDate);
            var resource = helpers.createArn('ram', accountId, 'user', user.UserName);

            var diffInDays = helpers.daysBetween(currentDate, loginDate);
            if (diffInDays >= 90) {
                var getUserProfile = helpers.addSource(cache, source,
                    ['ram', 'GetLoginProfile', region, user.UserName]);

                if (getUserProfile && getUserProfile.err && getUserProfile.err.Code && getUserProfile.err.Code == 'EntityNotExist.User.LoginProfile') {
                    helpers.addResult(results, 0, `RAM user inactive for ${diffInDays} days is not enabled`, region, resource);
                } else if (getUserProfile.err || !getUserProfile.data) {
                    helpers.addResult(results, 3, `Unable to query user login profile: ${helpers.addError(getUserProfile)}`, region, resource);
                } else {
                    helpers.addResult(results, 2, `RAM user inactive for ${diffInDays} days is enabled`, region, resource);
                }
            } else {
                helpers.addResult(results, 0,
                    `RAM user last activity was ${diffInDays} days ago`, region, resource);
            }
        }

        callback(null, results, source);
    }
};