const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Advanced Threat Protection Enabled',
    category: 'CosmosDB',
    description: 'Ensures that Advanced Threat Protection feature is enabled for Microsoft Azure Cosmos DB accounts.',
    more_info: 'Advanced Threat Protection for Azure Cosmos DB provides an additional layer of security intelligence that detects unusual and potentially harmful attempts to access or exploit Azure Cosmos DB accounts.',
    link: 'https://docs.microsoft.com/en-us/azure/cosmos-db/cosmos-db-advanced-threat-protection',
    recommended_action: 'Modify Microsoft Azure Cosmos DB accounts to enable advanced threat protection feature.',
    apis: ['databaseAccounts:list', 'advancedThreatProtection:get'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.databaseAccounts, function(location, rcb) {
            var databaseAccounts = helpers.addSource(cache, source,
                ['databaseAccounts', 'list', location]);

            if (!databaseAccounts) return rcb();

            if (databaseAccounts.err || !databaseAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for CosmosDB database accounts: ' + helpers.addError(databaseAccounts), location);
                return rcb();
            }

            if (!databaseAccounts.data.length) {
                helpers.addResult(results, 0, 'No CosmosDB database accounts found', location);
                return rcb();
            }

            async.each(databaseAccounts.data, (account, cb) => {
                if (!account.id) return cb();

                if(account.EnabledApiTypes &&
                    account.EnabledApiTypes === 'Sql') {
                    var advancedThreatProtection = helpers.addSource(cache, source,
                        ['advancedThreatProtection', 'get', location, account.id]);

                    if (!advancedThreatProtection || advancedThreatProtection.err || !advancedThreatProtection.data) {
                        helpers.addResult(results, 3,
                            `Unable to query advanced threat protection for CosmosDB database account: ${advancedThreatProtection}`,
                            location, account.id);
                    }

                    if (advancedThreatProtection.data.isEnabled) {
                        helpers.addResult(results, 0,
                            'Advanced threat protection is enabled for CosmosDB database account', location, account.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Advanced threat protection is not enabled for CosmosDB database account', location, account.id);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'Advanced threat protection feature is not supported for current resource', location, account.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
