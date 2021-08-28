var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Access Keys Rotation',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM user access keys are rotated after regular interval of time.',
    more_info: 'Access keys should be rotated to avoid having them accidentally exposed.',
    link: 'https://www.alibabacloud.com/help/doc-detail/152682.htm',
    recommended_action: 'Rotate the access keys every desired number of days',
    apis: ['RAM:ListUsers', 'RAM:ListAccessKeys', 'STS:GetCallerIdentity'],
    settings: {
        ram_access_keys_rotation_interval: {
            name: 'RAM User Access Keys Rotation Interval',
            description: 'Return a failing result when access keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var accessKeyRotationInterval = parseInt(settings.ram_access_keys_rotation_interval || this.settings.ram_access_keys_rotation_interval.default);
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

            var getAccessKey = helpers.addSource(cache, source,
                ['ram', 'ListAccessKeys', region, user.UserName]);
            
            if (getAccessKey.err || !getAccessKey.data) {
                helpers.addResult(results, 3,
                    'Unable to query user access keys' + helpers.addError(getAccessKey), region);
                continue;
            }

            let resource = helpers.createArn('ram', accountId, 'user', user.UserName);
            if (getAccessKey.data.AccessKeys && getAccessKey.data.AccessKeys.AccessKey && getAccessKey.data.AccessKeys.AccessKey.length) {
                let activeKeyFound = false;
                for (var accessKey of getAccessKey.data.AccessKeys.AccessKey) {
                    if (accessKey.Status && accessKey.Status == 'Active') {
                        activeKeyFound = true;
                        resource = resource + ':' + accessKey.AccessKeyId;
                        let createDate = accessKey.CreateDate;
                        var currentDate = new Date();
                        var createDateFormat = new Date(createDate);
        
                        var diffInDays = helpers.daysBetween(currentDate, createDateFormat);
                        if (diffInDays <= accessKeyRotationInterval) {
                            helpers.addResult(results, 0,
                                `RAM user access key was last rotated ${diffInDays} days ago which is equal to or less than ${accessKeyRotationInterval}`, region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `RAM user access key was last rotated ${diffInDays} days ago which is greater than ${accessKeyRotationInterval}`, region, resource);
                        }
                    }
                }
                if (!activeKeyFound) {
                    helpers.addResult(results, 0,
                        'RAM user does not have any active access keys', region, resource);
                }
            } else {
                helpers.addResult(results, 0,
                    'RAM user does not have any access keys', region, resource);
            }
        }

        callback(null, results, source);
    }
};
