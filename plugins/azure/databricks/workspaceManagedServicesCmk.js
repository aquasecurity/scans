var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Databricks Workspace Managed Services CMK Encrypted',
    category: 'AI & ML',
    owasp: ['LLM02', 'LLM04'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Databricks premium workspace managed services are encrypted with CMK.',
    more_info: 'Azure Databricks allows you to encrypt data in your workspace using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Using CMK encryption offers enhanced security and compliance, allowing centralized management and control of encryption keys through Azure Key Vault',
    recommended_action: 'Ensure that Databricks workspace managed services has CMK encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/databricks/security/keys/cmk-managed-disks-azure',
    apis: ['databricks:listWorkspaces'],
    realtime_triggers: ['microsoftdatabricks:workspaces:write','microsoftdatabricks:workspaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.databricks, function(location, rcb) {
            const databricks = helpers.addSource(cache, source,
                ['databricks', 'listWorkspaces', location]);

            if (!databricks) return rcb();
            
            if (databricks.err || !databricks.data) {
                helpers.addResult(results, 3, 'Unable to query for Databricks Workspaces: ' + helpers.addError(databricks), location);
                return rcb();
            }

            if (!databricks.data.length) {
                helpers.addResult(results, 0, 'No existing Databricks Workspaces found', location);
                return rcb();
            }

            for (let workspace of databricks.data) {

                if (workspace.sku && workspace.sku.name && workspace.sku.name.toLowerCase()!='premium') {
                    helpers.addResult(results, 0, 'Databricks workspace is not a premium workspace', location, workspace.id);
                } else if (workspace.encryption && workspace.encryption.entities && workspace.encryption.entities.managedServices) {
                    helpers.addResult(results, 0, 'Databricks workspace managed services has CMK encryption enabled', location, workspace.id);
                }  else {
                    helpers.addResult(results, 2, 'Databricks workspace managed services does not have CMK encryption enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};