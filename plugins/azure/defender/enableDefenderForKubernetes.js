var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Defender For Kubernetes',
    category: 'Defender',
    domain: 'Security',
    description: 'Enabling Microsoft Defender for Kubernetes allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC).',
    more_info: 'Turning on Microsoft Defender for Kubernetes enables threat detection for Kubernetes, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.',
    recommended_action: 'Turning on Microsoft Defender for Kubernetes incurs an additional cost per resource.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-detection-capabilities',
    apis: ['pricings:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.pricings, function(location, rcb) {
            var pricings = helpers.addSource(cache, source,
                ['pricings', 'list', location]);

            if (!pricings) return rcb();

            if (pricings.err || !pricings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Pricing: ' + helpers.addError(pricings), location);
                return rcb();
            }

            if (!pricings.data.length) {
                helpers.addResult(results, 0, 'No Pricing information found', location);
                return rcb();
            }

            let kubernetesService = pricings.data.find((pricing) => pricing.name.toLowerCase() === 'kubernetesservice');
            if (kubernetesService) {
                if (kubernetesService.pricingTier.toLowerCase() === 'standard') {
                    helpers.addResult(results, 0, 'Azure Defender is enabled for Kubernetes Service', location, kubernetesService.id);
                } else {
                    helpers.addResult(results, 2, 'Azure Defender is not enabled for Kubernetes Service', location, kubernetesService.id);
                }
            } else {
                helpers.addResult(results, 2, 'Azure Defender is not enabled for Kubernetes Service', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
