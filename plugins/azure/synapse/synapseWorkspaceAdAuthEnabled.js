var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Synapse Workspace AD Auth Enabled',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Synapse workspace has Active Directory (AD) authentication enabled.',
    more_info: 'Enabling Azure Active Directory authentication for Synapse workspace enhances security by ensuring that only authenticated and authorized users can access resources and eliminating the need for password storage. This integration simplifies permission management and secure access.',
    recommended_action: 'Enable Active Directory (AD) authentication mode for all Synapse workspace.',
    link: 'https://learn.microsoft.com/en-us/azure/synapse-analytics/sql/active-directory-authentication',
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
                
                if (workspace.azureADOnlyAuthentication) {
                    helpers.addResult(results, 0, 'Synapse workspace has Active Directory authentication enabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Synapse workspace does not have Active Directory authentication enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};