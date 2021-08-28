var async = require('async');
var helpers = require('../../../helpers/aws');

var managedAdminPolicy = 'arn:aws:iam::aws:policy/AdministratorAccess';

module.exports = {
    title: 'IAM User Admins',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures the number of IAM admins in the account are minimized',
    more_info: 'While at least two IAM admin users should be configured, the total number of admins should be kept to a minimum.',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.html',
    recommended_action: 'Keep two users with admin permissions but ensure other IAM users have more limited permissions.',
    apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies',
        'IAM:listPolicies' ,'IAM:getPolicy', 'IAM:getPolicyVersion' ,'IAM:listGroupsForUser',
        'IAM:listGroups', 'IAM:listGroupPolicies', 'IAM:listAttachedGroupPolicies',
        'IAM:getUserPolicy', 'IAM:getGroupPolicy'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. Limiting the number of IAM administrators ' +
             'reduces the scope of users with potential access to this data.'
    },
    settings: {
        iam_admin_count_minimum: {
            name: 'IAM Admin Count Minimum',
            description: 'The minimum number of IAM user admins to require in the account',
            regex: '^[0-9]{0,4}$',
            default: 2
        },
        iam_admin_count_maximum: {
            name: 'IAM Admin Count Maximum',
            description: 'The maximum number of IAM user admins to require in the account',
            regex: '^[0-9]{0,4}$',
            default: 2
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            // using the `in` operator because 0 is a valid setting
            iam_admin_count_minimum: 'iam_admin_count_minimum' in settings
                ? parseInt(settings.iam_admin_count_minimum)
                : this.settings.iam_admin_count_minimum.default,
            iam_admin_count_maximum: 'iam_admin_count_maximum' in settings
                ? parseInt(settings.iam_admin_count_maximum)
                : this.settings.iam_admin_count_maximum.default,
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        if (config.iam_admin_count_maximum < config.iam_admin_count_minimum) {
            helpers.addResult(results, 3,
                'IAM Admin Count Maximum cannot be less than IAM Admin Count Minimum');
            return callback(null, results, source);
        }

        var listUsers = helpers.addSource(cache, source,
            ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query for user IAM policy status: ' + helpers.addError(listUsers));
            return callback(null, results, source);
        }

        if (!listUsers.data.length) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }

        var userAdmins = [];

        async.each(listUsers.data, function(user, cb){
            if (!user.UserName) return cb();

            // Get managed policies attached to user
            var listAttachedUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedUserPolicies', region, user.UserName]);

            // Get inline policies attached to user
            var listUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listUserPolicies', region, user.UserName]);

            var listGroupsForUser = helpers.addSource(cache, source,
                ['iam', 'listGroupsForUser', region, user.UserName]);

            var getUserPolicy = helpers.addSource(cache, source,
                ['iam', 'getUserPolicy', region, user.UserName]);

            if (!listAttachedUserPolicies || listAttachedUserPolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for user: ' + user.UserName + ': ' + helpers.addError(listAttachedUserPolicies), 'global', user.Arn);
                return cb();
            }

            if (!listUserPolicies || listUserPolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM user policy for user: ' + user.UserName + ': ' + helpers.addError(listUserPolicies), 'global', user.Arn);
                return cb();
            }

            if (!listGroupsForUser || listGroupsForUser.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM user groups for user: ' + user.UserName + ': ' + helpers.addError(listGroupsForUser), 'global', user.Arn);
                return cb();
            }

            // See if user has admin managed policy
            if (listAttachedUserPolicies.data &&
                listAttachedUserPolicies.data.AttachedPolicies) {
                for (var a in listAttachedUserPolicies.data.AttachedPolicies) {
                    var policy = listAttachedUserPolicies.data.AttachedPolicies[a];
                    
                    if (!policy.PolicyArn) continue;

                    if (policy.PolicyArn === managedAdminPolicy) {
                        userAdmins.push({name: user.UserName, arn: user.Arn});
                        return cb();
                    }

                    var getPolicy = helpers.addSource(cache, source,
                        ['iam', 'getPolicy', region, policy.PolicyArn]);

                    if (getPolicy &&
                        getPolicy.data &&
                        getPolicy.data.Policy &&
                        getPolicy.data.Policy.DefaultVersionId) {
                        var getPolicyVersion = helpers.addSource(cache, source,
                            ['iam', 'getPolicyVersion', region, policy.PolicyArn]);

                        if (getPolicyVersion &&
                            getPolicyVersion.data &&
                            getPolicyVersion.data.PolicyVersion &&
                            getPolicyVersion.data.PolicyVersion.Document) {
                            let statements = helpers.normalizePolicyDocument(
                                getPolicyVersion.data.PolicyVersion.Document);
                            if (!statements) break;

                            // Loop through statements to see if admin privileges
                            for (let statement of statements) {
                                if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW' &&
                                statement.Action && statement.Action.indexOf('*') > -1 &&
                                statement.Resource && statement.Resource.indexOf('*') > -1) {
                                    userAdmins.push({name: user.UserName, arn: user.Arn});
                                    return cb();
                                }
                            }
                        }
                    }
                }
            }

            // See if user has admin inline policy
            if (listUserPolicies.data &&
                listUserPolicies.data.PolicyNames) {

                for (var p in listUserPolicies.data.PolicyNames) {
                    var policyName = listUserPolicies.data.PolicyNames[p];

                    if (getUserPolicy &&
                        getUserPolicy[policyName] &&
                        getUserPolicy[policyName].data &&
                        getUserPolicy[policyName].data.PolicyDocument) {

                        var statements = helpers.normalizePolicyDocument(
                            getUserPolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (var s in statements) {
                            var statement = statements[s];

                            if (statement.Effect === 'Allow' &&
                                statement.Action.indexOf('*') > -1 &&
                                statement.Resource &&
                                statement.Resource.indexOf('*') > -1) {
                                userAdmins.push({name: user.UserName, arn: user.Arn});
                                return cb();
                            }
                        }
                    }
                }
            }

            // See if user is in a group allowing admin access
            if (listGroupsForUser.data &&
                listGroupsForUser.data.Groups) {

                for (var g in listGroupsForUser.data.Groups) {
                    var group = listGroupsForUser.data.Groups[g];

                    // Get managed policies attached to group
                    var listAttachedGroupPolicies = helpers.addSource(cache, source,
                        ['iam', 'listAttachedGroupPolicies', region, group.GroupName]);

                    // Get inline policies attached to group
                    var listGroupPolicies = helpers.addSource(cache, source,
                        ['iam', 'listGroupPolicies', region, group.GroupName]);

                    var getGroupPolicy = helpers.addSource(cache, source,
                        ['iam', 'getGroupPolicy', region, group.GroupName]);

                    // See if group has admin managed policy
                    if (listAttachedGroupPolicies &&
                        listAttachedGroupPolicies.data &&
                        listAttachedGroupPolicies.data.AttachedPolicies) {

                        for (a in listAttachedGroupPolicies.data.AttachedPolicies) {
                            var policyAttached = listAttachedGroupPolicies.data.AttachedPolicies[a];

                            if (policyAttached.PolicyArn === managedAdminPolicy) {
                                userAdmins.push({name: user.UserName, arn: user.Arn});
                                return cb();
                            }
                        }
                    }

                    // See if group has admin inline policy
                    if (listGroupPolicies &&
                        listGroupPolicies.data &&
                        listGroupPolicies.data.PolicyNames) {

                        for (var q in listGroupPolicies.data.PolicyNames) {
                            var policyGroupName = listGroupPolicies.data.PolicyNames[q];

                            if (getGroupPolicy &&
                                getGroupPolicy[policyGroupName] &&
                                getGroupPolicy[policyGroupName].data &&
                                getGroupPolicy[policyGroupName].data.PolicyDocument) {

                                var statementsGroup = helpers.normalizePolicyDocument(
                                    getGroupPolicy[policyGroupName].data.PolicyDocument);
                                if (!statementsGroup) break;

                                // Loop through statements to see if admin privileges
                                for (s in statementsGroup) {
                                    var statementGroup = statementsGroup[s];

                                    if (statementGroup.Effect === 'Allow' &&
                                        statementGroup.Action.indexOf('*') > -1 &&
                                        statementGroup.Resource.indexOf('*') > -1) {
                                        userAdmins.push({name: user.UserName, arn: user.Arn});
                                        return cb();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            cb();
        }, function(){
            // Use admins array
            if (userAdmins.length < config.iam_admin_count_minimum) {
                helpers.addResult(results, 1,
                    'There are fewer than the minimum ' + config.iam_admin_count_minimum + ' IAM user administrators',
                    'global', null, custom);
            } else if (userAdmins.length >= config.iam_admin_count_minimum && userAdmins.length <= config.iam_admin_count_maximum) {
                helpers.addResult(results, 0,
                    'There are ' + userAdmins.length + ' IAM user administrators',
                    'global', null, custom);
            } else {
                for (var u in userAdmins) {
                    helpers.addResult(results, 2,
                        'User: ' + userAdmins[u].name + ' is one of ' + userAdmins.length + ' IAM user administrators, which exceeds the expected value of: ' + config.iam_admin_count_maximum,
                        'global', userAdmins[u].arn, custom);
                }
            }

            callback(null, results, source);
        });
    }
};