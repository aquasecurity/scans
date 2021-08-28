var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Lock Waits Flag Enabled',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures SQL instances for PostgreSQL type have log_lock_waits flag enabled.',
    more_info: 'SQL instance for PostgreSQL database provides log_lock_waits flag. It is not enabled by default. Enabling it will make sure that log messages are generated whenever a session waits longer than deadlock_timeout to acquire a lock.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags#config',
    recommended_action: 'Ensure that log_lock_waits flag is enabled for all PostgreSQL instances.',
    apis: ['instances:sql:list', 'projects:get'],

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
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === "READ_REPLICA_INSTANCE") return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('postgres')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of postgreSQL type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_lock_waits' &&
                                                                    flag.value && flag.value == 'on');
                    
                    if (found) {
                        helpers.addResult(results, 0, 
                            'SQL instance have log_lock_waits flag enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'SQL instance does not have log_lock_waits flag enabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have log_lock_waits flag enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}