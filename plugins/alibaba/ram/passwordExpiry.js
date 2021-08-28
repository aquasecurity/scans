var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password Expiry',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM password security settings require password to be expired after set number of days.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to require password to be expired after set number of days.',
    apis: ['RAM:GetPasswordPolicy'],
    settings: {
        ram_password_expiry: {
            name: 'RAM User Password Expiry',
            description: 'Maximum number of days after which RAM user password should be expired',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var getPasswordPolicy = helpers.addSource(cache, source,
            ['ram', 'GetPasswordPolicy', region]);

        var ramPasswordExpiry = parseInt(settings.ram_password_expiry || this.settings.ram_password_expiry.default);

        if (!getPasswordPolicy) return callback(null, results, source);

        if (getPasswordPolicy.err || !getPasswordPolicy.data || !Object.keys(getPasswordPolicy.data).length) {
            helpers.addResult(results, 3,
                'Unable to query RAM password policy: ' + helpers.addError(getPasswordPolicy), region);
            return callback(null, results, source);
        }

        if (getPasswordPolicy.data.MaxPasswordAge <= ramPasswordExpiry) {
            helpers.addResult(results, 0,
                `RAM password security policy requires password to be expired after ${getPasswordPolicy.data.MaxPasswordAge} days which is equal to or less than desired limit of ${ramPasswordExpiry}`, region);
        } else {
            helpers.addResult(results, 2,
                `RAM password security policy requires password to be expired after ${getPasswordPolicy.data.MaxPasswordAge} days which is greater than desired limit of ${ramPasswordExpiry}`, region);
        }

        callback(null, results, source);
    }
};