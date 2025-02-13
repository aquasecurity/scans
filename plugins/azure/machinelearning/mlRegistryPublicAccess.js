var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Machine Learning Registry Public Access Disabled',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that Azure Machine Learning registries are not publicly accessible.',
    more_info: 'Disabling public network access for Azure Machine Learning registries helps prevent data leakage risks by ensuring that your registries are not accessible over the public internet. Configuring network isolation with private endpoints prevents the network traffic from going over the public internet and brings Azure Machine Learning registry service to your Virtual network preventing exposure of sensitive data.',
    recommended_action: 'Ensure that Azure Machine Learning registries have public network access disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/machine-learning/how-to-registry-network-isolation',
    apis: ['machineLearning:listRegistries'],
    realtime_triggers: ['microsoftmachinelearningservices:registries:write','microsoftmachinelearningservices:registries:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.machineLearning, function(location, rcb) {
            var machineLearningRegistries = helpers.addSource(cache, source,
                ['machineLearning', 'listRegistries', location]);

            if (!machineLearningRegistries) return rcb();

            if (machineLearningRegistries.err || !machineLearningRegistries.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Machine Learning registries: ' + helpers.addError(machineLearningRegistries), location);
                return rcb();
            }

            if (!machineLearningRegistries.data.length) {
                helpers.addResult(results, 0, 'No existing Machine Learning registries found', location);
                return rcb();
            }

            for (let registry of machineLearningRegistries.data) {
                if (!registry.id) continue; 

                if (registry.publicNetworkAccess && registry.publicNetworkAccess.toLowerCase()=='disabled') {
                    helpers.addResult(results, 0,
                        'Machine Learning registry has public network access disabled', location, registry.id);
                } else {
                    helpers.addResult(results, 2,
                        'Machine Learning registry has public network access enabled', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};