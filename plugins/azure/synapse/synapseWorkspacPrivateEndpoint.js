var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Synapse Workspace Private Endpoints',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensure that Azure Synapse workspace is accessible only through managed private endpoints.',
    more_info: 'Enabling managed private endpoints for Azure Synapse Analytics workspace ensure secure, private communication between your Synapse workspace and other Azure resources, traversing exclusively over the Microsoft backbone network. It enhances security by protecting against data exfiltration and allowing connectivity only to specific approved resources.',
    recommended_action: 'Modify Synapse workspace and configure managed private endpoints.',
    link: 'https://learn.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints',
    apis: ['synapse:listWorkspaces'],
    realtime_triggers: ['microsoftsynapse:workspaces:write','microsoftsynapse:workspaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.synapse, function(location, rcb) {
            const workspaces = helpers.addSource(cache, source,
                ['synapse', 'listWorkspaces', location]);

            if (!workspaces) return rcb();


            if (workspaces.err || !workspaces.data) {
                helpers.addResult(results, 3, 'Unable to query Synapse workspaces: ' + helpers.addError(workspaces), location);
                return rcb();
            }

            if (!workspaces.data.length) {
                helpers.addResult(results, 0, 'No existing Synapse workspaces found', location);
                return rcb();
            }

            for (let workspace of workspaces.data) {
                if (!workspace.id) continue;
                
                if (workspace.privateEndpointConnections &&
                    workspace.privateEndpointConnections.length) {
                    helpers.addResult(results, 0, 'Synapse workspace has managed private endpoints configured', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Synapse workspace does not have managed private endpoints configured', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};