var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Workspace High Business Impact Enabled',
    category: 'AI & ML',
    owasp: ['LLM02'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Machine Learning workspaces have High Business Impact (HBI) feature enabled.',
    more_info: 'Enabling the High Business Impact (HBI) feature in Machine Learning workspaces controls the data Microsoft collects for diagnostics, prevents the transmission of confidential telemetry, and enhances encryption to protect sensitive business information while ensuring compliance with security protocols.',
    recommended_action: 'Ensures that High Business Impact (HBI) feature enabled for Machine Learning workspace.',
    link: 'https://learn.microsoft.com/en-us/azure/machine-learning/concept-data-encryption',
    apis: ['machineLearning:listWorkspaces'],
    realtime_triggers: ['microsoft:machinelearningservices:workspaces:write', 'microsoft:machinelearningservices:workspaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.machineLearning, function(location, rcb) {
            var machineLearningWorkspaces = helpers.addSource(cache, source,
                ['machineLearning', 'listWorkspaces', location]);

            if (!machineLearningWorkspaces) return rcb();

            if (machineLearningWorkspaces.err || !machineLearningWorkspaces.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Machine Learning workspaces: ' + helpers.addError(machineLearningWorkspaces), location);
                return rcb();
            }

            if (!machineLearningWorkspaces.data.length) {
                helpers.addResult(results, 0, 'No existing Machine Learning workspaces found', location);
                return rcb();
            }

            for (let workspace of machineLearningWorkspaces.data) {
                if (!workspace.id) continue; 

                if (workspace.hbiWorkspace) {
                    helpers.addResult(results, 0,
                        'Machine Learning workspace has high business impact (HBI) feature enabled', location, workspace.id);
                } else {
                    helpers.addResult(results, 2,
                        'Machine Learning workspace does not have high business impact (HBI) feature enabled', location, workspace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
