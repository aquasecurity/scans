var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'KMS User Separation',
    category: 'IAM',
    domain: 'Identity and Access Management',
    description: 'Ensures that no users have the KMS admin role and any one of the CryptoKey roles.',
    more_info: 'Ensuring that no users have the KMS admin role and any one of the CryptoKey roles follows separation of duties, where no user should have access to resources out of the scope of duty.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no service accounts have both the KMS admin role and any of CryptoKey roles attached.',
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
            var serviceAccountUsers = [];
            var notSeparated = [];
            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/cloudkms.admin') {
                    serviceAccountUsers = serviceAccountUsers.concat(roleBinding.members)
                }
            });

            iamPolicy.bindings.forEach(roleBinding => {
                if (roleBinding.role === 'roles/cloudkms.cryptoKeyDecrypter' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    }).concat(notSeparated);
                } else if (roleBinding.role === 'roles/cloudkms.cryptoKeyEncrypter' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    }).concat(notSeparated);
                } else if (roleBinding.role === 'roles/cloudkms.cryptoKeyEncrypterDecrypter' &&
                    roleBinding.members) {
                    notSeparated = roleBinding.members.filter(member => {
                        return (serviceAccountUsers.indexOf(member) > -1)
                    }).concat(notSeparated);
                }
            });

            if (notSeparated.length) {
                notSeparated = [...new Set(notSeparated)];
                notSeparated.forEach(account => {
                    let accountName = (account.includes(':')) ? account.split(':')[1] : account;
                    let resource = helpers.createResourceName('serviceAccounts', accountName, project);
                    helpers.addResult(results, 2,
                        `Account has the KMS admin role and one or more CryptoKey roles`, region, resource);
                });
            } else {
                helpers.addResult(results, 0, 'No accounts have a KMS admin role or a CryptoKey key role', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};