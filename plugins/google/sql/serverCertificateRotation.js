var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SSL Certificate Rotation',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that server certificates configured for Cloud SQL are rotated before they expire.',
    more_info: 'Server certificates configured for Cloud SQL DB instances should be rotated before they expire to ensure ' +
        'that incoming connections for database instance remain secure.',
    link: 'https://cloud.google.com/sql/docs/postgres/configure-ssl-instance?authuser=1#server-certs',
    recommended_action: 'Edit Cloud SQL DB instances and rotate server certificates under Connections->MANAGE CERTIFICATES',
    apis: ['instances:sql:list', 'projects:get'],
    settings: {
        server_certicate_expiration_threshold: {
            name: 'SQL Server Certificate Expiration Threshold',
            description: 'Number of days in future before which SSL certiciates should be rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '30'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            expiryThreshold: parseInt(settings.server_certicate_expiration_threshold || this.settings.server_certicate_expiration_threshold.default)
        };

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, projects.err);
            return callback(null, results, source);
        }

        let project = projects.data[0].name;

        async.each(regions.instances.sql, function(region, rcb) {
            let sqlInstances = helpers.addSource(
                cache, source, ['instances', 'sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }

            sqlInstances.data.forEach(sqlInstance => {
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() == "READ_REPLICA_INSTANCE") return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.serverCaCert &&
                    sqlInstance.serverCaCert.expirationTime) {
                    let certExpiry = sqlInstance.serverCaCert.expirationTime;
                    let difference = Math.round((new Date(certExpiry).getTime() - new Date().getTime())/(24*60*60*1000));
                    if (difference >= config.expiryThreshold) {
                        helpers.addResult(results, 0,
                            `SQL instance SSL certificate will expire after ${difference} days`, region, resource);
                    } else if (difference < 0) {
                        helpers.addResult(results, 2,
                            `SQL instance SSL certificate has already expired`, region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `SQL instance SSL certificate will expire after ${difference} days`, region, resource);
                    }
                } else {
                    helpers.addResult(results, 3,
                        'Unable to find certicite info for instance', region, resource);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
} 
