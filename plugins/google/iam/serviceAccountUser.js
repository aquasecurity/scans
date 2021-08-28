var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Account User',
    category: 'IAM',
    domain: 'Identity and Access Management',
    description: 'Ensures that no users have the Service Account User role.',
    more_info: 'The Service Account User role gives users the access to all service accounts of a project. This can result in an elevation of privileges and is not recommended.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no service accounts have the Service Account User role attached.',
    apis: ['projects:getIamPolicy', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.projects, function(region, rcb){
            let iamPolicies = helpers.addSource(cache, source,
                ['projects', 'getIamPolicy', region]);

            if (!iamPolicies) return rcb();

            if (iamPolicies.err || !iamPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for IAM policies', region, null, null, iamPolicies.err);
                return rcb();
            }

            if (!iamPolicies.data.length) {
                helpers.addResult(results, 0, 'No IAM policies found', region);
                return rcb();
            }

            var iamPolicy = iamPolicies.data[0];
            var serviceAccountExists = false;
            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/iam.serviceAccountUser') {
                    serviceAccountExists = true;
                    roleBinding.members.forEach(member => {
                        let accountName = (member.includes(':')) ? member.split(':')[1] : member;
                        let resource = helpers.createResourceName('serviceAccounts', accountName, project);
                        helpers.addResult(results, 2,
                            'The account has a service account user role', region, resource);
                    });
                }
            });

            if (!serviceAccountExists) {
                helpers.addResult(results, 0, 'No accounts have service account user roles', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};