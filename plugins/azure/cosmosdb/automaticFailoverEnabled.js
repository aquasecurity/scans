const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automatic Failover Enabled',
    category: 'Cosmos DB',
    domain: 'Databases',
    description: 'Ensure that the Automatic Failover feature is enabled for Microsoft Azure Cosmos DB accounts.',
    more_info: 'It is strongly recommended to configure the Azure Cosmos DB accounts used for production workloads to enable automatic failover. ' +
        'Automatic failover allows Azure Cosmos DB to automatically failover to the Azure cloud region with the highest failover priority when the source region become unavailable.',
    link: 'https://docs.microsoft.com/en-us/azure/cosmos-db/high-availability',
    recommended_action: 'Modify Cosmos DB account to enable automatic failover.',
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

                if (account.enableAutomaticFailover) {
                    helpers.addResult(results, 0,
                        'Automatic failover is enabled for Cosmos DB account', location, account.id);
                } else {
                    helpers.addResult(results, 2,
                        'Automatic failover is not enabled for Cosmos DB account', location, account.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
