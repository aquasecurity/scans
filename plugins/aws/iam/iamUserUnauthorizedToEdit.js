var async = require('async');
var helpers = require('../../../helpers/aws');

var adminAccessArn = 'arn:aws:iam::aws:policy/AdministratorAccess';
var iamFullAccessArn = 'arn:aws:iam::aws:policy/IAMFullAccess';

var iamEditAccessPermissions = [
    '*',
    'iam:*',
    'iam:CreatePolicy',
    'iam:CreatePolicyVersion',
    'iam:DeleteGroupPolicy',
    'iam:DeletePolicy',
    'iam:DeletePolicyVersion',
    'iam:DeleteRolePolicy',
    'iam:DeleteUserPolicy',
    'iam:DetachGroupPolicy',
    'iam:DetachRolePolicy',
    'iam:DetachUserPolicy',
    'iam:PutGroupPolicy',
    'iam:PutRolePolicy',
    'iam:PutUserPolicy',
    'iam:UpdateAssumeRolePolicy'
];

module.exports = {
    title: 'IAM User Unauthorized to Edit',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures AWS IAM users that are not authorized to edit IAM access policies are decommissioned.',
    more_info: 'Only authorized IAM users should have permission to edit IAM access policies to prevent any unauthorized requests.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html',
    recommended_action: 'Update unauthorized IAM users to remove permissions to edit IAM access policies.',
    apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies',
        'IAM:listGroupsForUser', 'IAM:listGroups', 'IAM:listGroupPolicies', 
        'IAM:listAttachedGroupPolicies', 'IAM:getUserPolicy', 'IAM:getGroupPolicy'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. Limiting the number of IAM administrators ' +
             'reduces the scope of users with potential access to this data.'
    },
    settings: {
        iam_authorized_user_arns: {
            name: 'IAM Authorized User ARNs',
            description: 'A comma delimited list of user ARNs authorized to contain edit IAM access policies permission',
            regex: '^arn:(aws[a-zA-Z-]*)?:iam::[0-9]{12}:.+$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var whitelisted_users = settings.iam_authorized_user_arns || this.settings.iam_authorized_user_arns.default;

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listUsers = helpers.addSource(cache, source,
            ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                `Unable to query for user IAM policy status: ${helpers.addError(listUsers)}`);
            return callback(null, results, source);
        }

        if (!helpers.isValidArray(listUsers.data)) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }

        var restrictedUser = {};

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
                    `Unable to query for IAM attached policy for user: ${user.UserName}: ${helpers.addError(listAttachedUserPolicies)}`, 'global', user.Arn);
                return cb();
            }
                
            if (!listUserPolicies || listUserPolicies.err) {
                helpers.addResult(results, 3,
                    `Unable to query for IAM user policy for user: ${user.UserName}: ${helpers.addError(listUserPolicies)}`, 'global', user.Arn);
                return cb();
            }

            if (!listGroupsForUser || listGroupsForUser.err) {
                helpers.addResult(results, 3,
                    `Unable to query for IAM user groups for user: ${user.UserName}: ${helpers.addError(listGroupsForUser)}`, 'global', user.Arn);
                return cb();
            }

            // See if user has administrator access or IAM full access
            if (listAttachedUserPolicies.data && listAttachedUserPolicies.data.AttachedPolicies) {
                for (var p in listAttachedUserPolicies.data.AttachedPolicies) {
                    let policy = listAttachedUserPolicies.data.AttachedPolicies[p];

                    if (policy.PolicyArn === adminAccessArn ||
                        policy.PolicyArn === iamFullAccessArn) {
                        addPolicyToUserObj(restrictedUser, user, policy.PolicyName);
                    }
                }
            }

            // See if user has IAM full access inline policy
            if (listUserPolicies.data.PolicyNames) {

                for (var up in listUserPolicies.data.PolicyNames) {
                    let policyName = listUserPolicies.data.PolicyNames[up];

                    if (getUserPolicy &&
                        getUserPolicy[policyName] &&
                        getUserPolicy[policyName].data &&
                        getUserPolicy[policyName].data.PolicyDocument) {

                        let statements = helpers.normalizePolicyDocument(
                            getUserPolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (var s in statements) {
                            let statement = statements[s];

                            if (helpers.userGlobalAccess(statement, iamEditAccessPermissions)) {
                                addPolicyToUserObj(restrictedUser, user, policyName);
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

                        for (var a in listAttachedGroupPolicies.data.AttachedPolicies) {
                            let policyAttached = listAttachedGroupPolicies.data.AttachedPolicies[a];
                            if (policyAttached.PolicyArn === adminAccessArn ||
                                policyAttached.PolicyArn === iamFullAccessArn) {
                                addPolicyToUserObj(restrictedUser, user, policyAttached.PolicyName);
                            }
                        }
                    }

                    // See if group has admin inline policy
                    if (listGroupPolicies &&
                        listGroupPolicies.data &&
                        listGroupPolicies.data.PolicyNames) {

                        for (var q in listGroupPolicies.data.PolicyNames) {
                            let policyGroupName = listGroupPolicies.data.PolicyNames[q];

                            if (getGroupPolicy &&
                                getGroupPolicy[policyGroupName] &&
                                getGroupPolicy[policyGroupName].data &&
                                getGroupPolicy[policyGroupName].data.PolicyDocument) {
                                var statementsGroup = helpers.normalizePolicyDocument(
                                    getGroupPolicy[policyGroupName].data.PolicyDocument);
                                if (!statementsGroup) break;

                                // Loop through statements to see if admin privileges
                                for (s in statementsGroup) {
                                    let statementGroup = statementsGroup[s];

                                    if (helpers.userGlobalAccess(statementGroup, iamEditAccessPermissions)) {
                                        addPolicyToUserObj(restrictedUser, user, policyGroupName);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (!restrictedUser[user.Arn]) {
                helpers.addResult(results, 0,
                    `IAM user "${user.UserName}" does not have edit access policies permission`,
                    'global', user.Arn);
            } else if (whitelisted_users.includes(user.Arn)) {
                helpers.addResult(results, 0,
                    `IAM user "${user.UserName}" is authorized to have edit access policies permission`,
                    'global', user.Arn);
            } else {
                helpers.addResult(results, 2,
                    `IAM user "${user.UserName}" is not authorized to have these policies attached: ${restrictedUser[user.Arn].policyNames.join(', ')}`,
                    'global', user.Arn);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};

function addPolicyToUserObj(userObj, user, policy) {
    if (userObj[user.Arn]) {
        if (!userObj[user.Arn].policyNames.includes(policy)) userObj[user.Arn].policyNames.push(policy);
    } else userObj[user.Arn] = {name: user.UserName, policyNames: [policy]};
}