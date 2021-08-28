var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Log Storage Encryption',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures BYOK encryption is properly configured in the Activity Log Storage Account',
    more_info: 'Storage accounts can be configured to encrypt data-at-rest. By default Azure will create a set of keys to encrypt the storage account, but the recommended approach is to create your own keys using Azure Key Vault.',
    recommended_action: 'Ensure the Storage Account used by Activity Logs is configured with a BYOK key.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption-customer-managed-keys',
    apis: ['storageAccounts:list', 'blobContainers:list', 'diagnosticSettingsOperations:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'Enabling encryption of log storage data helps to protect this data.',
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        var diagnosticContainers = {};
        var diagnosticSettingsOperations = helpers.addSource(cache, source,
            ['diagnosticSettingsOperations', 'list', 'global']);

        if (!diagnosticSettingsOperations || diagnosticSettingsOperations.err || !diagnosticSettingsOperations.data) {
            helpers.addResult(results, 3,
                'Unable to query for diagnostic settings: ' + helpers.addError(diagnosticSettingsOperations), 'global');
            return callback(null, results, source);
        }

        if (!diagnosticSettingsOperations.data.length) {
            helpers.addResult(results, 0,
                'No diagnostic settings found', 'global');
            return callback(null, results, source);
        }

        diagnosticSettingsOperations.data.forEach(diagnosticSettingsOperation => {
            if (diagnosticSettingsOperation.storageAccountId && diagnosticSettingsOperation.name) {
                if (!diagnosticContainers[diagnosticSettingsOperation.storageAccountId]) diagnosticContainers[diagnosticSettingsOperation.storageAccountId] = [];
                diagnosticContainers[diagnosticSettingsOperation.storageAccountId].push(diagnosticSettingsOperation.name.toLowerCase());
            }
        });

        async.each(locations.storageAccounts, function(location, rcb) {
            var storageAccounts = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for storage accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            let containerExists = false;

            storageAccounts.data.forEach(storageAccount => {
                let checkSA = false;
                
                const blobContainerList = helpers.addSource(cache, source,
                    ['blobContainers', 'list', location, storageAccount.id]);

                if (diagnosticContainers[storageAccount.id]) checkSA = true;

                if (!blobContainerList || blobContainerList.err || !blobContainerList.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for storage containers: ' + helpers.addError(blobContainerList), location, storageAccount.id);
                } else if (blobContainerList.data.length) {
                    blobContainerList.data.forEach(blobContainer => {
                        if (blobContainer.name) {
                            if (blobContainer.name.toLowerCase() === 'insights-operational-logs' ||
                                blobContainer.name.toLowerCase().indexOf('insights-logs-') > -1) {
                                checkSA = true;
                            }
                        }
                    });
                }

                if (checkSA) {
                    containerExists = true;

                    if (storageAccount.encryption &&
                        storageAccount.encryption.keySource &&
                        storageAccount.encryption.keySource.toLowerCase() == 'microsoft.keyvault') {
                        helpers.addResult(results, 0,
                            'Activity Logs container for the storage account is encrypted with BYOK', location, storageAccount.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Activity Logs container for the storage account is not encrypted with BYOK', location, storageAccount.id);
                    }
                }
            });

            if (!containerExists) {
                helpers.addResult(results, 0,
                    'No existing Storage Containers found for insight logs', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};