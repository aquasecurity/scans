var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Database SSL Enabled',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures SQL databases have SSL enabled',
    more_info: 'Enabling SSL ensures that the sensitive data being transferred from the database is encrypted.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: 'Ensure that SSL is enabled on all SQL databases.',
    apis: ['instances:sql:list', 'projects:get'],
    compliance: {
        pci: 'PCI requires strong cryptographic and security protocols ' +
             'when transmitting user data, this includes using SSL.',
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'Database SSL should be used to ensure SQL databases ' +
            'are always connecting through secure encryption.',
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, projects.err);
            return callback(null, results, source);
        }

        let project = projects.data[0].name;

        async.each(regions.instances.sql, function(region, rcb){
            let sqlInstances = helpers.addSource(cache, source,
                ['instances', 'sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region, null, null, sqlInstances.err);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }

            sqlInstances.data.forEach(sqlInstance => {
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === "READ_REPLICA_INSTANCE") return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.settings &&
                    sqlInstance.settings.ipConfiguration &&
                    sqlInstance.settings.ipConfiguration.requireSsl) {
                    helpers.addResult(results, 0,
                        'SQL database has SSL enabled', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'SQL database has SSL disabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}