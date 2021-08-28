var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Accounts AAD Enabled',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures that identity-based Directory Service for Azure File Authentication is enabled for all Azure Files',
    more_info: 'Enabling identity-based Authentication ensures that only the authorized Active Directory members can access or connect to the file shares, enforcing granular access control.',
    recommended_action: 'Ensure that identity-based Directory Service for Azure File Authentication is enabled for all Azure File Shares.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/files/storage-files-active-directory-overview',
    apis: ['storageAccounts:list', 'fileShares:list'],
    settings: {
        storage_account_check_file_share: {
            name: 'Storage Account Check for File Share',
            description: 'When set to true Plugin will check if storage account has any active file shares',
            regex: '^(true|false)$',
            default: 'false'
        },
        storage_account_encryption_allow_pattern: {
            name: 'Storage Accounts Encryption Allow Pattern',
            description: 'When set, whitelists storage accounts matching the given pattern. Useful for overriding storage accounts that require default encryption.',
            regex: '^.{1,255}$',
            default: '^aquaacct([a-f0-9]){16}$'
        }
    },
    run: function(cache, settings, callback) {
        var config = {
            storage_account_check_file_share: settings.storage_account_check_file_share || this.settings.storage_account_check_file_share.default,
            storage_account_encryption_allow_pattern: settings.storage_account_encryption_allow_pattern || this.settings.storage_account_encryption_allow_pattern.default
        };
        config.storage_account_check_file_share = (config.storage_account_check_file_share == 'true');

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb){
            var storageAccounts = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            var allowRegex = (config.storage_account_encryption_allow_pattern &&
                config.storage_account_encryption_allow_pattern.length) ? new RegExp(config.storage_account_encryption_allow_pattern) : false;

            storageAccounts.data.forEach(function(storageAccount){
                if (allowRegex && allowRegex.test(storageAccount.name)) {
                    helpers.addResult(results, 0,
                        'Storage account: ' + storageAccount.name + ' is whitelisted via custom setting.',
                        location, storageAccount.id, custom);
                } else {
                    if (storageAccount.enableAzureFilesAadIntegration) {
                        helpers.addResult(results, 0, 'Storage Account is configured with AAD Authentication', location, storageAccount.id);
                    } else if (config.storage_account_check_file_share) {
                        var fileShares = helpers.addSource(cache, source,
                            ['fileShares', 'list', location, storageAccount.id]);

                        if (!fileShares || fileShares.err && !fileShares.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for file shares: ' + helpers.addError(fileShares), location, storageAccount.id);
                        } else {
                            if (!fileShares.data.length) {
                                helpers.addResult(results, 0, 'Storage Account is not configured with AAD Authentication but no file shares are present', location, storageAccount.id);
                            } else {
                                helpers.addResult(results, 2, 'Storage Account is not configured with AAD Authentication', location, storageAccount.id);
                            }
                        }
                    } else {
                        helpers.addResult(results, 2, 'Storage Account is not configured with AAD Authentication', location, storageAccount.id);
                    }
                }

            });
            
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};