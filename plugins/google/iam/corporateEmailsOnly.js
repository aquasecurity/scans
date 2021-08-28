var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Corporate Emails Only',
    category: 'IAM',
    domain: 'Identity and Access Management',
    description: 'Ensures that no users are using their Gmail accounts for access to GCP.',
    more_info: 'Gmail accounts are personally created and are not controlled by organizations. Fully managed accounts are recommended for increased visibility, auditing and control over access to resources.',
    link: 'https://cloud.google.com/iam/docs/overview',
    recommended_action: 'Ensure that no users are actively using their Gmail accounts to access GCP.',
    apis: ['projects:getIamPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

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
            var gmailUsers = [];
            if (iamPolicy.bindings) {
                iamPolicy.bindings.forEach(roleBinding => {
                    if (roleBinding.members && roleBinding.members.length) {
                        roleBinding.members.forEach(member => {
                            var emailArr = member.split('@');
                            if (emailArr.length && emailArr.length > 1) {
                                var provider = emailArr[1].split('.');
                                if (provider[0] === 'gmail' && (gmailUsers.indexOf(member) === -1)) {
                                    gmailUsers.push(member);
                                }
                            }
                        })
                    }
                });
            }

            if (gmailUsers.length) {
                gmailUsers.forEach(user => {
                    helpers.addResult(results, 2,
                        'Account is using Gmail login credentials', region, user);
                });
            } else {
                helpers.addResult(results, 0, 'No accounts are using Gmail login credentials', region);
            }


            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};