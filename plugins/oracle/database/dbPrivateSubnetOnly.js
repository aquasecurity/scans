var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'DB Private Subnet Only',
    category: 'Database',
    domain: 'Databases',
    description: 'Ensures that all database systems are in private subnets only.',
    more_info: 'Database systems in private subnets ensure that access to the database can ' +
        'only be from within the internal architecture, following security best practices.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/dbaas_security.htm',
    recommended_action: 'When creating a new database, ensure that that subnet it is being ' +
        'launched in is a private subnet.',
    apis: ['vcn:list', 'dbSystem:list', 'subnet:list'],
    compliance: {
        hipaa: 'DB systems should only be launched in private subnets and ' +
            'accessed through private endpoints. Exposing DB systems to ' +
            'the public network may increase the risk of access from ' +
            'disallowed parties. HIPAA requires strict access and integrity ' +
            'controls around sensitive data.',
        pci: 'PCI requires DB systems to be properly secured. Ensure ' +
            'DB systems are not accessible from the Internet and ' +
            'use proper jump box access mechanisms.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.dbSystem, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {
                const dbSystems = helpers.addSource(cache, source,
                    ['dbSystem', 'list', region]);

                if (!dbSystems || dbSystems.err || !dbSystems.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for database systems: ' + helpers.addError(dbSystems), region);
                    return rcb();
                }

                if (!dbSystems.data.length) {
                    helpers.addResult(results, 0, 'No database systems found', region);
                    return rcb();
                }

                const subnets = helpers.addSource(cache, source,
                    ['subnet', 'list', region]);

                if (!subnets || subnets.err || !subnets.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for subnets: ' + helpers.addError(subnets), region);
                    return rcb();
                }

                if (!subnets.data.length) {
                    helpers.addResult(results, 0, 'No subnets found', region);
                    return rcb();
                }

                var privateSubnets = [];
                subnets.data.forEach(subnet => {
                    if (subnet.id) {
                        if (subnet.prohibitPublicIpOnVnic) {
                            privateSubnets.push(subnet.id);
                        }
                    }
                });

                dbSystems.data.forEach(dbSystem => {
                    if (dbSystem.lifecycleState === "AVAILABLE") {
                        if (dbSystem.subnetId && (privateSubnets.indexOf(dbSystem.subnetId) > -1)) {
                            helpers.addResult(results, 0, 'The DB system is in a private subnet', region, dbSystem.id);
                        } else {
                            helpers.addResult(results, 2, 'The DB system is in a public subnet', region, dbSystem.id);
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