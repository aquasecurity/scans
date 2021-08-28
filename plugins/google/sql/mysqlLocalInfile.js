var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'MySQL Local Infile Disabled',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures SQL instances for MySQL type does not have local infile flag enabled.',
    more_info: 'SQL instances for MySQL type database provides local_infile flag, which can be used to load data from client or server systems. It controls the load data statements for database. Anyone using this server can access any file on the client system. For security reasons it should be disabled.',
    link: 'https://cloud.google.com/sql/docs/mysql/flags',
    recommended_action: 'Ensure that local infile flag is disabled for all MySQL instances.',
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

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('mysql')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of MySQL type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'local_infile' &&
                                                                        flag.value && flag.value == 'off');
                        
                    if (found) {
                        helpers.addResult(results, 0, 
                            'SQL instance does not have local_infile flag enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'SQL instance has local_infile flag enabled', region, resource);

                    }
                } else {
                    helpers.addResult(results, 2,
                        'SQL instance has local_infile flag enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
