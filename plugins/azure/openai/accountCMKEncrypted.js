var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'OpenAI Account CMK Encrypted',
    category: 'AI & ML',
    owasp: ['LLM02', 'LLM04'],
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensures that Azure OpenAI accounts are encrypted using CMK.',
    more_info: 'Azure OpenAI allows you to encrypt your accounts using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Using CMK encryption provides enhanced security control over data and the ability to manage and audit key access, ensuring that sensitive data processed by Azure OpenAI models remains protected.',
    recommended_action: 'Ensure that Azure OpenAI accounts have CMK encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/ai-services/openai/encrypt-data-at-rest',
    apis: ['openAI:listAccounts'],
    realtime_triggers: ['microsoftcognitiveservices:accounts:write','microsoftcognitiveservices:accounts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.openAI, function(location, rcb) {
            const accounts = helpers.addSource(cache, source,
                ['openAI', 'listAccounts', location]);

            if (!accounts) return rcb();


            if (accounts.err || !accounts.data) {
                helpers.addResult(results, 3, 'Unable to query OpenAI accounts: ' + helpers.addError(accounts), location);
                return rcb();
            }

            if (!accounts.data.length) {
                helpers.addResult(results, 0, 'No existing OpenAI accounts found', location);
                return rcb();
            }

            for (let account of accounts.data) {

                if (account.properties && account.properties.encryption &&
                    account.properties.encryption.keySource &&
                    account.properties.encryption.keySource.toLowerCase() == 'microsoft.keyvault') {
                    helpers.addResult(results, 0,
                        'OpenAI Account is encrypted using CMK', location, account.id);
                } else {
                    helpers.addResult(results, 2,
                        'OpenAI Account is not encrypted using CMK', location, account.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};