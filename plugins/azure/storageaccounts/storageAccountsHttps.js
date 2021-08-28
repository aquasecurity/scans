var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Accounts HTTPS',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures HTTPS-only traffic is allowed to storage account endpoints',
    more_info: 'Storage Accounts can contain sensitive information and should only be accessed over HTTPS. Enabling the HTTPS-only flag ensures that Azure does not allow HTTP traffic to Storage Accounts.',
    recommended_action: 'Enable the HTTPS-only option for all Storage Accounts.',
    link: 'https://docs.microsoft.com/en-us/azure/governance/policy/samples/ensure-https-storage-account',
    apis: ['storageAccounts:list'],
    remediation_min_version: '202006260310',
    remediation_description: 'The HTTPS-only option will be enabled for the storage account',
    apis_remediate: ['storageAccounts:list'],
    actions: {remediate:['storageAccounts:update'], rollback:['storageAccounts:update']},
    permissions: {remediate: ['storageAccounts:update'], rollback: ['storageAccounts:update']},
    realtime_triggers: ['microsoftstorage:storageaccounts:write'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'Storage Account HTTPS should be used to ensure all data access ' +
                'connects over a secure channel.',
        pci: 'All card holder data must be transmitted over secure channels. ' +
                'Storage Account HTTPS should be used to ensure all data access ' +
                'connects over a secure channel.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb){
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
            } else {
                for (var acct in storageAccount.data) {
                    var account = storageAccount.data[acct];

                    if (account.enableHttpsTrafficOnly || account.supportsHttpsTrafficOnly) {
                        helpers.addResult(results, 0, 'Storage Account is configured with HTTPS-only traffic', location, account.id);
                    } else {
                        helpers.addResult(results, 2, 'Storage Account is not configured with HTTPS-only traffic', location, account.id);
                    }
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'storageAccountsHttps';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2019-06-01';
        var method = 'PATCH';

        // for logging purposes
        var storageAccountNameArr = resource.split('/');
        var storageAccountName = storageAccountNameArr[storageAccountNameArr.length - 1];

        // create the params necessary for the remediation
        var body = {
            'properties': {
                'supportsHttpsTrafficOnly': true
            }

        };

        // logging
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'enableHttpsTrafficOnly': 'Disabled',
            'storageAccount': storageAccountName
        };

        helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
            if (err) return callback(err);
            if (action) action.action = putCall;


            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'Enabled'
            };

            callback(null, action);
        });
    }
};