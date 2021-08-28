var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password Minimum Length',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM password security settings require minimum length of 14 or above.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to require the minimum length of 14 or above.',
    apis: ['RAM:GetPasswordPolicy'],
    compliance: {
        pci: 'PCI requires a strong password policy. Setting Identity password ' +
             'requirements enforces this policy.'
    },
    settings: {
        ram_password_min_length: {
            name: 'RAM User Password Minimum Length',
            description: 'Minimum password length required for RAM user login passwords. Should be 14 or above',
            regex: '^1[4-9]|[2-9]{2,3}$',
            default: '14'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var minPasswordLength = parseInt(settings.ram_password_min_length || this.settings.ram_password_min_length.default);

        var getPasswordPolicy = helpers.addSource(cache, source,
            ['ram', 'GetPasswordPolicy', region]);

        if (!getPasswordPolicy) return callback(null, results, source);

        if (getPasswordPolicy.err || !getPasswordPolicy.data || !Object.keys(getPasswordPolicy.data).length) {
            helpers.addResult(results, 3,
                'Unable to query RAM password policy: ' + helpers.addError(getPasswordPolicy), region);
            return callback(null, results, source);
        }

        if (getPasswordPolicy.data.MinimumPasswordLength >= minPasswordLength) {
            helpers.addResult(results, 0,
                `RAM password security policy requires minimum length of ${getPasswordPolicy.data.MinimumPasswordLength} which is equal to or greater than desired limit of ${minPasswordLength}`, region);
        } else {
            helpers.addResult(results, 2,
                `RAM password security policy requires minimum length of ${getPasswordPolicy.data.MinimumPasswordLength} which is less than desired limit of ${minPasswordLength}`, region);
        }

        callback(null, results, source);
    }
};