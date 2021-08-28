var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Group Inline Policies',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures that groups do not have any inline policies',
    more_info: 'Managed Policies are recommended over inline policies.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html',
    recommended_action: 'Remove inline policies attached to groups',
    apis: ['IAM:listGroups', 'IAM:listGroupPolicies'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listGroups = helpers.addSource(cache, source,
            ['iam', 'listGroups', region]);

        if (!listGroups) return callback(null, results, source);

        if (listGroups.err || !listGroups.data) {
            helpers.addResult(results, 3,
                'Unable to query for groups: ' + helpers.addError(listGroups));
            return callback(null, results, source);
        }

        if (!listGroups.data.length) {
            helpers.addResult(results, 0, 'No groups found');
            return callback(null, results, source);
        }

        async.each(listGroups.data, function(group, cb){
            if (!group.GroupName) return cb();

            var listGroupPolicies = helpers.addSource(cache, source,
                ['iam', 'listGroupPolicies', region, group.GroupName]);

            if (!listGroupPolicies || listGroupPolicies.err || !listGroupPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query inline policies for group: ' + group.GroupName + ': ' + helpers.addError(listGroupPolicies),
                    'global', group.Arn);
                return cb();
            }
            
            if (!listGroupPolicies.data.PolicyNames || !listGroupPolicies.data.PolicyNames.length) {
                helpers.addResult(results, 0,
                    'Group: ' + group.GroupName + ' does not contain any inline policy',
                    'global', group.Arn);
            } else {
                helpers.addResult(results, 2,
                    'Group: ' + group.GroupName + ' contains ' + listGroupPolicies.data.PolicyNames.length + ' inline policy(s)',
                    'global', group.Arn);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};