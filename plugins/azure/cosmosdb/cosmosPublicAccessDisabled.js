const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Cosmos DB Public Access Disabled',
    category: 'Cosmos DB',
    domain: 'Databases',
    description: 'Ensure that Microsoft Azure Cosmos DB accounts are configured to deny public access.',
    more_info: 'Microsoft Azure Cosmos DB accounts should not be accessible from internet and only be accessed from within a VNET.',
    link: 'https://docs.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall',
    recommended_action: 'Modify firewall and the virtual network configuration for your Cosmos DB accounts to provide access to selected networks.',
    apis: ['databaseAccounts:list'],

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
                    'Unable to query for Cosmos DB accounts: ' + helpers.addError(databaseAccounts), location);
                return rcb();
            }

            if (!databaseAccounts.data.length) {
                helpers.addResult(results, 0, 'No Cosmos DB accounts found', location);
                return rcb();
            }

            databaseAccounts.data.forEach(account => {
                if (!account.id) return;

                if (account.isVirtualNetworkFilterEnabled && account.ipRules && account.ipRules.length) {
                    helpers.addResult(results, 0,
                        'Cosmos DB account denies public access', location, account.id);
                } else {
                    helpers.addResult(results, 2,
                        'Cosmos DB account allows public access', location, account.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
