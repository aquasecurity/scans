var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Access Keys Rotated',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures access keys are not older than 180 days in order to reduce accidental exposures',
    more_info: 'Access keys should be rotated frequently to avoid having them accidentally exposed.',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html',
    recommended_action: 'To rotate an access key, first create a new key, replace the key and secret throughout your app or scripts, then set the previous key to disabled. Once you ensure that no services are broken, then fully delete the old key.',
    apis: ['IAM:generateCredentialReport'],
    compliance: {
        hipaa: 'Rotating access keys helps to ensure that those keys have note been ' +
                'compromised. HIPAA requires strict controls around authentication of ' +
                'users or systems accessing HIPAA-compliant environments.',
        pci: 'PCI requires that all user credentials are rotated every 90 days. While ' +
             'IAM roles handle rotation automatically, access keys need to be manually ' +
             'rotated.',
        cis1: '1.4 Ensure access keys are rotated every 90 days or less'
    },
    settings: {
        access_keys_rotated_fail: {
            name: 'Access Keys Rotated Fail',
            description: 'Return a failing result when access keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 180
        },
        access_keys_rotated_warn: {
            name: 'Access Keys Rotated Warn',
            description: 'Return a warning result when access keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 90
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            access_keys_rotated_fail: settings.access_keys_rotated_fail || this.settings.access_keys_rotated_fail.default,
            access_keys_rotated_warn: settings.access_keys_rotated_warn || this.settings.access_keys_rotated_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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

        if (generateCredentialReport.data.length == 1) {
            helpers.addResult(results, 0, 'No IAM user accounts found');
            return callback(null, results, source);
        }

        var found = false;

        function addAccessKeyResults(lastRotated, keyNum, arn, userCreationTime) {
            var returnMsg = 'User access key ' + keyNum + ' ' + ((lastRotated === 'N/A' || !lastRotated) ? 'has never been rotated' : 'was last rotated ' + helpers.daysAgo(lastRotated) + ' days ago');

            if (helpers.daysAgo(userCreationTime) > config.access_keys_rotated_fail &&
                (!lastRotated || lastRotated === 'N/A' || helpers.daysAgo(lastRotated) > config.access_keys_rotated_fail)) {
                helpers.addResult(results, 2, returnMsg, 'global', arn, custom);
            } else if (helpers.daysAgo(userCreationTime) > config.access_keys_rotated_warn &&
                (!lastRotated || lastRotated === 'N/A' || helpers.daysAgo(lastRotated) > config.access_keys_rotated_warn)) {
                helpers.addResult(results, 1, returnMsg, 'global', arn, custom);
            } else {
                helpers.addResult(results, 0,
                    'User access key '  + keyNum + ' ' +
                    ((lastRotated === 'N/A') ? 'has never been rotated but user is only ' + helpers.daysAgo(userCreationTime) + ' days old' : 'was last rotated ' + helpers.daysAgo(lastRotated) + ' days ago'), 'global', arn, custom);
            }

            found = true;
        }

        async.each(generateCredentialReport.data, function(obj, cb){
            // TODO: update to handle booleans
            // The root account security is handled in a different plugin
            if (obj.user === '<root_account>') return cb();

            if (obj.access_key_1_active) {
                addAccessKeyResults(obj.access_key_1_last_rotated, '1', obj.arn + ':access_key_1', obj.user_creation_time);
            }

            if (obj.access_key_2_active) {
                addAccessKeyResults(obj.access_key_2_last_rotated, '2', obj.arn + ':access_key_2', obj.user_creation_time);
            }

            cb();
        }, function(){
            if (!found) {
                helpers.addResult(results, 0, 'No IAM user accounts using access keys found');
            }

            callback(null, results, source);
        });
    }
};