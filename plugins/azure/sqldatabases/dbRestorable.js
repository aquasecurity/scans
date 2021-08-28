const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'DB Restorable',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures SQL Database instances can be restored to a recent point',
    more_info: 'Automated backups of SQL databases with recent restore points help ensure that database recovery operations can occur without significant data loss.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-recovery-using-backups',
    recommended_action: 'Ensure that each SQL database has automated backups configured with a sufficient retention period and that the last known backup operation completes successfully.',
    apis: ['servers:listSql', 'databases:listByServer'],
    compliance: {
        hipaa: 'HIPAA requires backups of all user data ' +
            'and inventory to ensure future availability.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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
            servers.data.forEach(function(server) {
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
                        // Loop through databases
                        databases.data.forEach(function(database) {
                            if (database.earliestRestoreDate) {
                                helpers.addResult(results, 0,
                                    'SQL Database is restorable', location, database.id);
                            } else {
                                helpers.addResult(results, 2,
                                    'SQL Database is not restorable', location, database.id);
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
