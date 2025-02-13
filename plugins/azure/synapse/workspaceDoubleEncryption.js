var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Synapse Workspace Double Encryption Enabled',
    category: 'AI & ML',
    owasp: ['LLM10', 'LLM04', 'LLM02'],
    domain: 'Machine Learning',
    severity: 'High',
    description: 'Ensures that Azure Synapse workspaces have double Encryption enabled.',
    more_info: 'Enabling double encryption for Synapse workspace provides an extra layer of protection for data at rest and in transit. This feature significantly enhances security and helps ensure compliance with stringent data protection standards within the Azure environment.',
    recommended_action: 'Create a new Synapse workspace and enable double encryption using CMK.',
    link: 'https://learn.microsoft.com/en-us/azure/synapse-analytics/security/workspaces-encryption',
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
                
                if (workspace.encryption && 
                    workspace.encryption.doubleEncryptionEnabled &&
                    Object.entries(workspace.encryption.cmk).length > 0) {
                    helpers.addResult(results, 0, 'Synapse workspace has double encryption enabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2, 'Synapse workspace does not have double encryption enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};