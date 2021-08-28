var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Users Password And Keys',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Detects whether users with a console password are also using access keys',
    more_info: 'Access keys should only be assigned to machine users and should not be used for accounts that have console password access.',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
    recommended_action: 'Remove access keys from all users with console access.',
    apis: ['IAM:generateCredentialReport'],
    settings: {
        iam_machine_username_regex: {
            name: 'IAM Machine User Name Regex',
            description: 'Only inspect users that match this regex',
            regex: '^.*$',
            default: '^.*$'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        try {
            var machineUsernameRegex = RegExp(settings.iam_machine_username_regex || this.settings.iam_machine_username_regex.default);
        } catch (err) {
            helpers.addResult(results, 3, 'Invalid regex for machine username: ' + machineUsernameRegex, 'global');
        }

        var generateCredentialReport = helpers.addSource(cache, source, ['iam', 'generateCredentialReport', region]);

        if (!generateCredentialReport) return callback(null, results, source);

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3, 'Unable to query for users: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        if (generateCredentialReport.data.length === 1) {
            helpers.addResult(results, 0, 'No users with console access found');
            return callback(null, results, source);
        }

        var found = false;

        async.each(generateCredentialReport.data, function(obj, cb){
            // The root account security is handled in a different plugin
            if (obj.user === '<root_account>') return cb();
            if (!machineUsernameRegex.test(obj.user)) return cb();
            if (!obj.password_enabled) return cb();

            found = true;

            if (obj.access_key_1_active || obj.access_key_2_active) {
                helpers.addResult(results, 2, 'User has console access and access key', 'global', obj.arn);
            } else {
                helpers.addResult(results, 0, 'User has console access and no access keys', 'global', obj.arn);
            }

            cb();
        }, function(){
            if (!found) {
                helpers.addResult(results, 0, 'No users with console access and access keys found');
            }

            callback(null, results, source);
        });
    }
};