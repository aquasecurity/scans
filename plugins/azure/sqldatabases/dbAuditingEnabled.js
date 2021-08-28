var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Database Auditing Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures that SQL Database Auditing is enabled',
    more_info: 'Enabling SQL Database Auditing ensures that all database activities are being logged properly, including potential malicious activity.',
    recommended_action: 'Ensure that auditing is enabled for each SQL database.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-enable-auditing-on-sql-databases',
    apis: ['servers:listSql', 'databases:listByServer', 'databaseBlobAuditingPolicies:get'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {
            var servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            // Loop through servers and check databases
            servers.data.forEach(function(server){
                var databases = helpers.addSource(cache, source,
                    ['databases', 'listByServer', location, server.id]);

                if (!databases || databases.err || !databases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL server databases: ' + helpers.addError(databases), location, server.id);
                } else {
                    if (!databases.data.length) {
                        helpers.addResult(results, 0,
                            'No databases found for SQL server', location, server.id);
                    } else {
                        // Loop through databases and add policies
                        databases.data.forEach(function(database){
                            var databaseBlobAuditingPolicies = helpers.addSource(cache, source,
                                ['databaseBlobAuditingPolicies', 'get', location, database.id]);

                            if (!databaseBlobAuditingPolicies || databaseBlobAuditingPolicies.err || !databaseBlobAuditingPolicies.data) {
                                helpers.addResult(results, 3,
                                    'Unable to query for SQL server database auditing policies: ' + helpers.addError(databaseBlobAuditingPolicies), location, database.id);
                            } else {
                                if (!databaseBlobAuditingPolicies.data.length) {
                                    helpers.addResult(results, 2,
                                        'SQL server database does not contain auditing policies', location, database.id);
                                } else {
                                    databaseBlobAuditingPolicies.data.forEach(function(policy){
                                        if (policy.state &&
                                            policy.state.toLowerCase() == 'enabled') {
                                            helpers.addResult(results, 0, 'Database Auditing is enabled on the SQL database', location, policy.id);
                                        } else {
                                            helpers.addResult(results, 2, 'Database Auditing is not enabled on the SQL database', location, policy.id);
                                        }
                                    });
                                }
                            }
                        });
                    }
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
