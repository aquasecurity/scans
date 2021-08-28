var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Users Email Verified',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure all IAM user accounts have a valid and current email address.',
    more_info: 'To Have a valid email address associated with an OCI IAM local user account enables you to tie the account to identity in your organization ' +
        'as well as allows that user to reset their password if it is forgotten or lost.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingusers.htm',
    recommended_action: 'Modify IAM users to add their email addresses',
    apis: ['user:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var users = helpers.addSource(cache, source,
            ['user', 'list', region]);

        if (!users) return callback(null, results, source);

        if (users.err || !users.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(users));
            return callback(null, results, source);
        }

        if (users.data.length < 2) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }

        users.data.forEach(user => {
            if (!user.id || !user.name) return;

            if (user.email && user.email.length && user.emailVerified) {
                helpers.addResult(results, 0, `Email for user ${user.name} is verified`, region, user.id);
            } else if (!user.email || !user.email.length) {
                helpers.addResult(results, 2, `Email for user ${user.name} not found`, region, user.id);
            } else {
                helpers.addResult(results, 2, `Email for user ${user.name} is not verified`, region, user.id);
            }
        });

        callback(null, results, source);
    }
};
