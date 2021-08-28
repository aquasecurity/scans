var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Point in Time Restore Backup Retention',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures that Microsoft Azure SQL databases have a sufficient Point in Time Restore (PITR) backup retention period configured',
    more_info: 'Point-in-time restore is a self-service capability, which enables you to restore a database from backups to any point within the retention period. Point-in-time restore is useful in recovery scenarios, such as incidents caused by errors, incorrectly loaded data, or deletion of crucial data.',
    recommended_action: 'Ensure that an optimal backup retention period is set for Azure SQL databases.',
    link: 'https://azure.microsoft.com/en-us/blog/azure-sql-database-point-in-time-restore/',
    apis: ['servers:listSql', 'databases:listByServer', 'backupShortTermRetentionPolicies:listByDatabase'],
    settings: {
        pitr_backup_retention_period: {
            name: 'Point in Time Restore Backup Retention Period',
            default: '7',
            description: 'Desired number of days for which backups will be retained.',
            regex: '^(3[0-5]|2[0-9]|1[0-9]|[1-9])$'
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            retentionDays: parseInt(settings.pitr_backup_retention_period || this.settings.pitr_backup_retention_period.default)
        };

        async.each(locations.servers, function(location, rcb) {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
            }

            async.each(servers.data, function(server, scb) {
                const databases = helpers.addSource(cache, source,
                    ['databases', 'listByServer', location, server.id]);

                if (!databases || databases.err || !databases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL server databases: ' + helpers.addError(databases), location, server.id);
                    return scb();
                }
                
                if (!databases.data.length) {
                    helpers.addResult(results, 0,
                        'No databases found for SQL server', location, server.id);
                    return scb();
                }
                
                for (const database of databases.data) {
                    const policies = helpers.addSource(cache, source,
                        ['backupShortTermRetentionPolicies', 'listByDatabase', location, database.id]);
                    
                    if (!policies || policies.err || !policies.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for SQL database retention policies: ' + helpers.addError(policies), location, database.id);
                        continue;
                    }
                    
                    if (!policies.data.length) {
                        helpers.addResult(results, 0,
                            'No retention policies found for SQL database', location, database.id);
                        continue;
                    }
                    
                    for (const policy of policies.data) {
                        let retentionDays = 0;
                        if (policy.retentionDays){
                            retentionDays =  policy.retentionDays;
                        }

                        if (retentionDays >= config.retentionDays) {
                            helpers.addResult(results, 0,
                                `SQL Database is configured to retain backups for ${retentionDays} of ${config.retentionDays} days desired limit`,
                                location, database.id);
                        } else {
                            helpers.addResult(results, 2,
                                `SQL Database is configured to retain backups for ${retentionDays} of ${config.retentionDays} days desired limit`,
                                location, database.id);
                        }
                    }
                }
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
