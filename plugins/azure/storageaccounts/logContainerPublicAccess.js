const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Container Public Access',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures that the Activity Log Container does not have public read access',
    more_info: 'The container used to store Activity Log data should not be exposed publicly to avoid data exposure of sensitive activity logs.',
    recommended_action: 'Ensure the access level for the storage account containing Activity Log data is set to private.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/blobs/storage-manage-access-to-resources',
    apis: ['storageAccounts:list', 'blobContainers:list', 'diagnosticSettingsOperations:list'],
    compliance: {
        hipaa: 'HIPAA requires that all systems used for storing ' +
                'covered and user data must deny-all activity by ' +
                'default, along with keeping all data private ' +
                'and secure.'
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
                const blobContainerList = helpers.addSource(cache, source,
                    ['blobContainers', 'list', location, storageAccount.id]);

                let saBlobs = [];
                if (diagnosticContainers[storageAccount.id]) saBlobs = diagnosticContainers[storageAccount.id];

                if (!blobContainerList || blobContainerList.err || !blobContainerList.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for storage containers: ' + helpers.addError(blobContainerList), location, storageAccount.id);
                } else if (!blobContainerList.data.length) {
                    helpers.addResult(results, 0, 'No existing storage containers found', location, storageAccount.id);
                } else {
                    blobContainerList.data.forEach(blobContainer => {
                        if (blobContainer.name) {
                            if (blobContainer.name.toLowerCase() === 'insights-operational-logs' ||
                                blobContainer.name.toLowerCase().indexOf('insights-logs-') > -1 ||
                                saBlobs.indexOf(blobContainer.name.toLowerCase()) > -1) {
                                containerExists = true;
                                if (blobContainer.publicAccess &&
                                    blobContainer.publicAccess.toLowerCase() == 'none') {
                                    helpers.addResult(results, 0,
                                        'Storage container storing the activity logs is not publicly accessible', location, blobContainer.id);
                                } else {
                                    helpers.addResult(results, 2,
                                        'Storage container storing the activity logs is publicly accessible', location, blobContainer.id);
                                }
                            }
                        }
                    });
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
