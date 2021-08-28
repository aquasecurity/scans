var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Checkpoints Enabled',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that log_checkpoints flag is enabled for PostgreSQL instances.',
    more_info: 'When log_checkpoints flag is enabled, instance checkpoints and restart points are logged in the server log.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag',
    recommended_action: 'Ensure that all PostgreSQL database instances have log_checkpoints flag and it value is set to on.',
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

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toUpperCase().startsWith('POSTGRES')) {
                    helpers.addResult(results, 0, 'SQL instance database version is not of PosgreSQL type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_checkpoints' &&
                                                                        flag.value && flag.value == 'on');
                    if (found) {
                        helpers.addResult(results, 0,
                            'PostgreSQL instance has log_checkpoints flag enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'PostgreSQL instance does not have log_checkpoints flag enabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'PostgreSQL instance does not have log_checkpoints flag enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
