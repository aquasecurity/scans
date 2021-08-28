var async = require('async');
var helpers = require('../../../helpers/aws');

var managedAdminPolicy = 'arn:aws:iam::aws:policy/AdministratorAccess';

module.exports = {
    title: 'Lambda Admin Privileges',
    category: 'Lambda',
    domain: 'Serverless',
    description: 'Ensures no Lambda function available in your AWS account has admin privileges.',
    more_info: 'AWS Lambda Function should have most-restrictive IAM permissions for Lambda security best practices.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html',
    recommended_action: 'Modify IAM role attached with Lambda function to provide the minimal amount of access required to perform its tasks',
    apis: ['Lambda:listFunctions', 'IAM:listRoles', 'IAM:listAttachedRolePolicies', 'IAM:listRolePolicies',
        'IAM:listPolicies', 'IAM:getPolicy', 'IAM:getPolicyVersion', 'IAM:getRolePolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Lambda functions: ${helpers.addError(listFunctions)}`, region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            async.each(listFunctions.data, function(lambdaFunc, fcb){
                if (!lambdaFunc.FunctionArn) return fcb();

                var resource = lambdaFunc.FunctionArn;
                var adminPrivileged;

                if (!lambdaFunc.Role) {
                    helpers.addResult(results, 2,
                        'Function does not have a role attached', region, resource);
                    return fcb();
                }

                var roleNameArr = lambdaFunc.Role.split('/');
                var roleName = roleNameArr[roleNameArr.length - 1];

                var listAttachedRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listAttachedRolePolicies', defaultRegion, roleName]);
                var listRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listRolePolicies', defaultRegion, roleName]);
                var getRolePolicy = helpers.addSource(cache, source,
                    ['iam', 'getRolePolicy', defaultRegion, roleName]);

                if (!listAttachedRolePolicies ||
                    listAttachedRolePolicies.err ||
                    !listAttachedRolePolicies.data ||
                    !listAttachedRolePolicies.data.AttachedPolicies) {
                    helpers.addResult(results, 3,
                        `Unable to query for IAM attached policy for role "${roleName}": ${helpers.addError(listAttachedRolePolicies)}`,
                        region, resource);
                    return fcb();
                }

                if (!listRolePolicies || listRolePolicies.err || !listRolePolicies.data || !listRolePolicies.data.PolicyNames) {
                    helpers.addResult(results, 3,
                        `Unable to query for IAM role policy for role "${roleName}": ${helpers.addError(listRolePolicies)}`, 
                        region, resource);
                    return fcb();
                }

                for (var policy of listAttachedRolePolicies.data.AttachedPolicies) {
                    if (!policy.PolicyArn) continue;

                    if (policy.PolicyArn === managedAdminPolicy) {
                        helpers.addResult(results, 2,
                            'Function has admin privileges', region, resource);
                        return fcb();
                    }

                    var getPolicy = helpers.addSource(cache, source,
                        ['iam', 'getPolicy', defaultRegion, policy.PolicyArn]);

                    if (getPolicy &&
                        getPolicy.data &&
                        getPolicy.data.Policy &&
                        getPolicy.data.Policy.DefaultVersionId) {
                        var getPolicyVersion = helpers.addSource(cache, source,
                            ['iam', 'getPolicyVersion', defaultRegion, policy.PolicyArn]);

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
                                    adminPrivileged = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (adminPrivileged) break;
                }

                for (var policyName of listRolePolicies.data.PolicyNames) {
                    if (getRolePolicy &&
                        getRolePolicy[policyName] && 
                        getRolePolicy[policyName].data &&
                        getRolePolicy[policyName].data.PolicyDocument) {
                        let statements = helpers.normalizePolicyDocument(
                            getRolePolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (let statement of statements) {
                            if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW' &&
                            statement.Action && statement.Action.indexOf('*') > -1 &&
                            statement.Resource && statement.Resource.indexOf('*') > -1) {
                                adminPrivileged = true;
                                break;
                            }
                        }
                    }
                }

                if (!adminPrivileged) {
                    helpers.addResult(results, 0,
                        'Function does not have admin privileges', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Function has admin privileges', region, resource);
                }

                fcb();
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
