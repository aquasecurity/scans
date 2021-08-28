var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Username Matches Regex',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures all IAM user names match the given regex',
    more_info: 'Many organizational policies require IAM user names to follow a common naming convention. This check ensures these conventions are followed.',
    recommended_action: 'Rename the IAM user name to match the provided regex.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html',
    apis: ['IAM:generateCredentialReport'],
    settings: {
        iam_username_regex: {
            name: 'IAM User Name Regex',
            description: 'All IAM user names must match this regex',
            regex: '^.*$',
            default: '^.*$',
        },
    },
    asl: {
        conditions: [
            {
                service: 'iam',
                api: 'generateCredentialReport',
                property: 'user',
                transform: 'STRING',
                op: 'MATCHES',
                value: '^.*$'
            }
        ]
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var usernameRegex = RegExp(this.settings.iam_username_regex.default);
        try {
            usernameRegex = RegExp(settings.iam_username_regex || this.settings.iam_username_regex.default);
        } catch (err) {
            helpers.addResult(results, 3, err.message, 'global', this.settings.iam_username_regex.name);
        }

        var region = helpers.defaultRegion(settings);

        var generateCredentialReport = helpers.addSource(cache, source, ['iam', 'generateCredentialReport', region]);

        if (!generateCredentialReport) {
            return callback(null, results, source);
        }

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3, 'Unable to query for users: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        async.each(generateCredentialReport.data, function(user, cb) {
            var username = user.user;

            // ignore the root account name
            if (!username || username === '<root_account>') {
                helpers.addResult(results, 0, 'Root account', 'global', user.arn);
                return cb();
            }

            if (usernameRegex.test(username)) {
                helpers.addResult(results, 0, 'IAM username matches regex', 'global', user.arn);
                return cb();
            }

            helpers.addResult(results, 2, 'IAM username improperly named', 'global', user.arn);
            return cb();
        }, function() {
            callback(null, results, source);
        });
    }
};
