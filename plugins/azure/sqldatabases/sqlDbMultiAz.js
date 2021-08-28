const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL DB Multiple AZ',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures that SQL Database instances are created to be cross-AZ for high availability',
    more_info: 'Creating SQL Database instances in a single availability zone creates a single point of failure for all systems relying on that database. All SQL Database instances should be created in multiple availability zones to ensure proper failover.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-high-availability#zone-redundant-configuration',
    recommended_action: 'Ensure that each SQL Database is configured to be zone redundant.',
    apis: ['servers:listSql', 'databases:listByServer'],

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
                            if (database.zoneRedundant) {
                                helpers.addResult(results, 0,
                                    'SQL Database has zone redundancy enabled', location, database.id);
                            } else {
                                helpers.addResult(results, 2,
                                    'SQL Database does not have zone redundancy enabled', location, database.id);
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