var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'OpenAI Account Public Access Disabled',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensures that Azure OpenAI accounts are not publicly accessible.',
    more_info: 'Making OpenAI accounts publicly accessible can expose sensitive data and AI-generated content to unauthorized users, increasing the risk of data breaches and misuse of AI resources, which could lead to significant security and privacy concerns.',
    recommended_action: 'Ensure that Azure OpenAI have public network access disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/ai-services/cognitive-services-virtual-networks?tabs=portal#use-private-endpoints',
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

                if (account.properties &&
                    account.properties.publicNetworkAccess &&
                    account.properties.publicNetworkAccess.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 2,
                        'OpenAI Account is publicly accessible', location, account.id);
                } else {
                    helpers.addResult(results, 0,
                        'OpenAI Account is not publicly accessible', location, account.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};