var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password No Reuse',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM password security settings are set to prevent reusing desired number of previous passwords.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to prevent reusing desired number of previous passwords.',
    apis: ['RAM:GetPasswordPolicy'],
    settings: {
        ram_password_no_reuse_limit: {
            name: 'RAM User Password No Reuse Limit',
            description: 'Maximum number of previous user passwords which should not be reused',
            regex: '^[5-9]|[0-9]{2,3}$',
            default: '5'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var ramPasswordReuse = parseInt(settings.ram_password_no_reuse_limit || this.settings.ram_password_no_reuse_limit.default);

        var getPasswordPolicy = helpers.addSource(cache, source,
            ['ram', 'GetPasswordPolicy', region]);

        if (!getPasswordPolicy) return callback(null, results, source);

        if (getPasswordPolicy.err || !getPasswordPolicy.data || !Object.keys(getPasswordPolicy.data).length) {
            helpers.addResult(results, 3,
                'Unable to query RAM password policy: ' + helpers.addError(getPasswordPolicy), region);
            return callback(null, results, source);
        }

        if (getPasswordPolicy.data.PasswordReusePrevention >= ramPasswordReuse) {
            helpers.addResult(results, 0,
                `RAM password security policy requires to prevent reusing previous ${getPasswordPolicy.data.PasswordReusePrevention} passwords which is equal to or greater than desired limit of ${ramPasswordReuse}`, region);
        } else {
            helpers.addResult(results, 2,
                `RAM password security policy requires to prevent reusing previous ${getPasswordPolicy.data.PasswordReusePrevention} passwords which is less than desired limit of ${ramPasswordReuse}`, region);
        }

        callback(null, results, source);
    }
};