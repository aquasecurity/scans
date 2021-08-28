var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Access Keys Extra',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Detects the use of more than one access key by any single user',
    more_info: 'Having more than one access key for a single user increases the chance of accidental exposure. Each account should only have one key that defines the users permissions.',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
    recommended_action: 'Remove the extra access key for the specified user.',
    apis: ['IAM:generateCredentialReport'],
    asl: {
        conditions: [
            {
                service: 'iam',
                api: 'generateCredentialReport',
                property: 'access_key_1_active',
                op: 'ISFALSE'
            },
            {
                service: 'iam',
                api: 'generateCredentialReport',
                property: 'access_key_2_active',
                op: 'ISFALSE',
                logical: 'OR'
            }
        ]
    },
    run: function(cache, settings, callback) {

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

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
            if (obj.user === '<root_account>') return cb();

            if (obj.access_key_1_active && obj.access_key_2_active) {
                helpers.addResult(results, 2, 'User is using both access keys', 'global', obj.arn);
            } else {
                helpers.addResult(results, 0, 'User is not using both access keys', 'global', obj.arn);
            }

            found = true;

            cb();
        }, function(){
            if (!found) {
                helpers.addResult(results, 0, 'No users using both access keys found');
            }

            callback(null, results, source);
        });
    }
};