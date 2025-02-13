var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'OpenAI Account Managed Identity Enabled',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures a system or user assigned managed identity is enabled to authenticate to Azure OpenAI accounts.',
    more_info: 'Enabling managed identity for Azure OpenAI accounts automates credential management, enhancing security by avoiding hard-coded credentials and simplifying access control to Azure services.',
    recommended_action: 'Enable system or user-assigned identities for all Azure OpenAI accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/managed-identity',
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

                if (account.identity && account.identity.type && 
                    (account.identity.type.toLowerCase() === 'systemassigned' || account.identity.type.toLowerCase() === 'userassigned')) {
                    helpers.addResult(results, 0,
                        'OpenAI Account has managed identity enabled', location, account.id);
                } else {
                    helpers.addResult(results, 2,
                        'OpenAI Account does not have managed identity enabled', location, account.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};