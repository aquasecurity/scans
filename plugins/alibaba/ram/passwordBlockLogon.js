var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Password Block Logon',
    category: 'RAM',
    domain: 'Identity and Access Management',
    description: 'Ensure that RAM password security settings require logon to be blocked after maximum of 5 incorrect login attempts.',
    more_info: 'A strong password policy enforces minimum length, expiration, reuse, and symbol usage.',
    link: 'https://www.alibabacloud.com/help/doc-detail/116413.htm',
    recommended_action: 'Update the password security settings to require logon to be blocked after maximum of 5 or less incorrect login attempts.',
    apis: ['RAM:GetPasswordPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var getPasswordPolicy = helpers.addSource(cache, source,
            ['ram', 'GetPasswordPolicy', region]);

        if (!getPasswordPolicy) return callback(null, results, source);

        if (getPasswordPolicy.err || !getPasswordPolicy.data || !Object.keys(getPasswordPolicy.data).length) {
            helpers.addResult(results, 3,
                'Unable to query RAM password policy: ' + helpers.addError(getPasswordPolicy), region);
            return callback(null, results, source);
        }

        if (getPasswordPolicy.data.MaxLoginAttemps > 0 && getPasswordPolicy.data.MaxLoginAttemps <= 5) {
            helpers.addResult(results, 0,
                'RAM password security policy requires logon to be blocked after 5 attempts', region);
        } else {
            helpers.addResult(results, 2,
                'RAM password security policy does not require logon to be blocked after 5 attempts', region);
        }

        callback(null, results, source);
    }
};