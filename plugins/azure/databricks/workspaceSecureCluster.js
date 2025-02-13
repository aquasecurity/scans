var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Databricks Workspace Secure Cluster',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Databricks Workspace has secure cluster connectivity enabled.',
    more_info: 'Enabling the No Public IP feature on Azure Databricks workspace secures cluster connectivity by ensuring that virtual networks have no open ports and compute resources are without public IP addresses. This approach enhances security by reducing the attack surface and simplifying network configuration.',
    recommended_action: 'Ensure that Databricks workspace has secure cluster connectivity enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/databricks/security/network/classic/secure-cluster-connectivity',
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
                if (!workspace.id) continue;

                if (workspace.parameters && workspace.parameters.enableNoPublicIp && workspace.parameters.enableNoPublicIp.value) {
                    helpers.addResult(results, 0, 'Databricks workspace has secure cluster connectivity enabled', location, workspace.id);
                }  else {
                    helpers.addResult(results, 2, 'Databricks workspace does not have secure cluster connectivity enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};