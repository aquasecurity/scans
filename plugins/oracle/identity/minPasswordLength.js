var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Minimum Password Length',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensures password policy requires a minimum password length.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/managingpasswordrules.htm',
    recommended_action: 'Update the password policy to require a minimum password length.',
    apis: ['authenticationPolicy:get'],
    compliance: {
		pci: 'PCI requires a strong password policy. Setting Identity password ' +
			 'requirements enforces this policy.',
        hipaa: 'HIPAA requires a minimum password length of eight characters.'
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
                passwordPolicy.minimumPasswordLength) {
                if (passwordPolicy.minimumPasswordLength >= 14) {
                    helpers.addResult(results, 0, 'Minimum password length of: ' + passwordPolicy.minimumPasswordLength + ' is suitable', 'global', authenticationPolicy.data.compartmentId);
                } else if (passwordPolicy &&
                    passwordPolicy.minimumPasswordLength &&
                    passwordPolicy.minimumPasswordLength < 10) {
                    helpers.addResult(results, 2, 'Minimum password length of: ' + passwordPolicy.minimumPasswordLength + ' is less than the recommended 14 characters', 'global', authenticationPolicy.data.compartmentId);
                } else if (passwordPolicy &&
                    passwordPolicy.minimumPasswordLength &&
                    passwordPolicy.minimumPasswordLength < 14) {
                    helpers.addResult(results, 1, 'Minimum password length of: ' + passwordPolicy.minimumPasswordLength + ' is less than the recommended 14 characters', 'global', authenticationPolicy.data.compartmentId);
                } else {
                    helpers.addResult(results, 2,
                        'Password policy does not require a minimum password length', 'global', authenticationPolicy.data.compartmentId);
                }
            } else {
                helpers.addResult(results, 2,
                    'Password policy does not require a minimum password length', 'global', authenticationPolicy.data.compartmentId);
            }
        });

        callback(null, results, source);
    }
};