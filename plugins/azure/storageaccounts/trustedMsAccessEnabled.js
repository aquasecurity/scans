var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Trusted MS Access Enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures that Trusted Microsoft Services Access is enabled on Storage Accounts',
    more_info: 'Enabling firewall rules on Storage Accounts blocks all access by default. To ensure that Microsoft and Azure services that connect to the Storage Account still retain access, trusted Microsoft services should be allowed to access the storage account.',
    recommended_action: 'For each Storage Account, configure an exception for trusted Microsoft services.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security',
    apis: ['storageAccounts:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb) {
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            storageAccount.data.forEach(account => {
                if (account.networkAcls && 
                    account.networkAcls.bypass &&
                    account.networkAcls.bypass.toLowerCase().indexOf('azureservices') > -1) {
                    helpers.addResult(results, 0, 'Storage Account is set to allow trusted Microsoft services', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Storage Account is not set to allow trusted Microsoft services', location, account.id);
                }
            });
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};