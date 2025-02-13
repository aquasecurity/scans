var async = require('async');

var helpers = require('../../../helpers/azure');


module.exports = {
    title: 'VM Scale Set VNet Integrated',
    category: 'Virtual Machine Scale Set',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that Azure Virtual Machine scale sets has VNet integrated.',
    more_info: 'You can divide a virtual network into multiple subnets for organization and security. NICs connected to subnets (same or different) within a virtual network can communicate with each other without any extra configuration.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-networking',
    recommended_action: 'Modify VM scale set and configure a VNet.',
    apis: ['vmScaleSet:listAll'],
    realtime_triggers: ['microsoftcompute:virtualmachinescalesets:write', 'microsoftcompute:virtualmachinescalesets:delete','microsoftnetwork:virtualnetworks:subnets:write','microsoftnetwork:virtualnetworks:subnets:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.vmScaleSet, function(location, rcb) {

            var vmScaleSets = helpers.addSource(cache, source, ['vmScaleSet', 'listAll', location]);

            if (!vmScaleSets) return rcb();

            if (vmScaleSets.err || !vmScaleSets.data) {
                helpers.addResult(results, 3, 'Unable to query for VM scale sets: ' + helpers.addError(vmScaleSets), location);
                return rcb();
            }
            if (!vmScaleSets.data.length) {
                helpers.addResult(results, 0, 'No existing VM scale sets found', location);
                return rcb();
            }
            for (let set of vmScaleSets.data) {
                if (!set.id) continue;
                let networkInterfaceConfigs = set.virtualMachineProfile.networkProfile.networkInterfaceConfigurations[0];
                if (networkInterfaceConfigs && networkInterfaceConfigs.properties && networkInterfaceConfigs.properties.ipConfigurations[0] && networkInterfaceConfigs.properties.ipConfigurations[0].properties.subnet && networkInterfaceConfigs.properties.ipConfigurations[0].properties.subnet.id) {
                    helpers.addResult(results, 0, 'VM scale set has VNet Integrated', location, set.id);
                } else {
                    helpers.addResult(results, 2, 'VM scale set does not have VNet Integrated', location, set.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};