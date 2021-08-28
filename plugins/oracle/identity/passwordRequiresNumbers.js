var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Password Requires Numbers',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensures password policy requires at least one number.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingpasswordrules.htm',
    recommended_action: 'Update the password policy to require the use of numbers.',
    apis: ['authenticationPolicy:get'],
    compliance: {
        pci: 'PCI requires a strong password policy. Setting Identity password ' +
             'requirements enforces this policy.'
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var defaultRegion = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var authenticationPolicy = helpers.addSource(cache, source,
            ['authenticationPolicy', 'get', defaultRegion]);

        if (!authenticationPolicy) return callback(null, results, source);

        if (authenticationPolicy.err || !authenticationPolicy.data) {
            helpers.addResult(results, 3,
                'Unable to query for password policy status: ' + helpers.addError(authenticationPolicy));
            return callback(null, results, source);
        }

        if (!Object.keys(authenticationPolicy.data).length) {
            helpers.addResult(results, 0, 'No password policies found');
            return callback(null, results, source);
        }

        authenticationPolicy.data.forEach(policy => {
            var passwordPolicy = policy.passwordPolicy;
            if (passwordPolicy &&
                passwordPolicy.isNumericCharactersRequired) {
                helpers.addResult(results, 0,
                    'Password policy requires numeric characters', 'global', authenticationPolicy.data.compartmentId);
            } else {
                helpers.addResult(results, 1,
                    'Password policy does not require numeric characters', 'global', authenticationPolicy.data.compartmentId);
            }

        });

        callback(null, results, source);
    }
};