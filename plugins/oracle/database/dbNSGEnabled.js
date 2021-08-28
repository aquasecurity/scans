var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'DB Network Security Groups Enabled',
    category: 'Database',
    domain: 'Databases',
    description: 'Ensures that all databases have network security groups enabled.',
    more_info: 'Enabling network security groups on database systems allow for fine grain control over network access to the database, ensuring databases are only accessible from trusted entities and following security best practices.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Database/Tasks/backingupOS.htm',
    recommended_action: 'Ensure that all databases have network security groups enabled.',
    apis: ['dbSystem:list'],
    compliance: {
        hipaa: 'Database systems should only be launched in VCN environments and ' +
            'accessed through private endpoints. Exposing database systems to ' +
            'the public network may increase the risk of access from ' +
            'disallowed parties. HIPAA requires strict access and integrity ' +
            'controls around sensitive data.',
        pci: 'PCI requires database systems to be properly firewalled. ' +
            'Ensure database systems are using network security groups to ' +
            'control access. '
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.dbSystem, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var databases = helpers.addSource(cache, source,
                    ['dbSystem', 'list', region]);

                if (!databases) return rcb();

                if (databases.err || !databases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for database systems: ' + helpers.addError(databases), region);
                    return rcb();
                }

                if (!databases.data.length) {
                    helpers.addResult(results, 0, 'No database systems found', region);
                    return rcb();
                }
                databases.data.forEach(database => {
                    if (database.lifecycleState === "AVAILABLE") {
                        if (database.nsgIds &&
                            database.nsgIds.length) {
                            helpers.addResult(results, 0, 'The database system has network security groups enabled', region, database.id);
                        } else {
                            helpers.addResult(results, 2, 'The database system has network security groups disabled', region, database.id);

                        }
                    }
                });
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};