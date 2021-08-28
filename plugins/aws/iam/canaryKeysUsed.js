var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Canary Keys Used',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Detects when a special canary-token access key has been used',
    more_info: 'Canary access keys can be created with limited permissions and then used to detect when a potential breach occurs.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
    recommended_action: 'Create a canary access token and provide its user to CloudSploit. If CloudSploit detects that the account is in use, it will trigger a failure.',
    apis: ['IAM:generateCredentialReport'],
    settings: {
        canary_user: {
            name: 'Canary User',
            description: 'Provide a single IAM user name (not an ARN) to monitor for this account.',
            regex: '^[A-Za-z0-9_+=,@.-]{1,64}$',
            default: ''
        }
    },
    //we need to check if (canary_user && access_key_1_last_used_date) || (canary_user && access_key_2_last_used_date) [SOP]
    // canary_user && (access_key_1_last_used_date || access_key_2_last_used_date)
    asl: {
        conditions: [
            {
                service: 'iam',
                api: 'generateCredentialReport',
                property: 'access_key_1_last_rotated',
                transform: 'DAYSFROM',
                op: 'GT',
                value: 90
            }
        ]
    },
    run: function(cache, settings, callback) {
        var config = {
            canary_user: settings.canary_user || this.settings.canary_user.default
        };

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        if (!config.canary_user ||
            !config.canary_user.length) return callback(null, results, source);

        var generateCredentialReport = helpers.addSource(cache, source,
            ['iam', 'generateCredentialReport', region]);

        if (!generateCredentialReport) return callback(null, results, source);

        if (generateCredentialReport.err || !generateCredentialReport.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(generateCredentialReport));
            return callback(null, results, source);
        }

        if (generateCredentialReport.data.length <= 2) {
            helpers.addResult(results, 0, 'No users using access keys found');
            return callback(null, results, source);
        }

        var found = false;

        async.each(generateCredentialReport.data, function(obj, cb){
            // The root account security is handled in a different plugin
            if (obj.user !== config.canary_user) return cb();
            found = true;

            if (obj.access_key_1_last_used_date ||
                obj.access_key_2_last_used_date) {
                helpers.addResult(results, 2, 'The canary user: ' + config.canary_user + ' has been used.');
            } else {
                helpers.addResult(results, 0, 'The canary user: ' + config.canary_user + ' has not been used.');
            }

            cb();
        }, function(){
            if (!found) {
                helpers.addResult(results, 3, 'The canary user specified in the config could not be found.');
            }

            callback(null, results, source);
        });
    }
};