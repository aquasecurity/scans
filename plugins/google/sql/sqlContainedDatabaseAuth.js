var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL Contained Database Authentication',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures SQL instances of SQL Server type have Contained Database Authentication flag disabled.',
    more_info: 'Enabling Contained Database Authentication flag allows users to connect to the database without authenticating ' +
        'a login at the Database Engine level along with other security threats.',
    link: 'https://cloud.google.com/sql/docs/sqlserver/flags',
    recommended_action: 'Ensure that Contained Database Authentication flag is disabled for all SQL Server instances.',
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

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('sqlserver')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of SQL Server type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                        let found = sqlInstance.settings.databaseFlags.find(flag => flag.name &&
                            flag.name == 'contained database authentication' && flag.value && flag.value == 'off');

                        if (found) {
                            helpers.addResult(results, 0,
                                'SQL instance has contained database authentication flag disabled', region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                'SQL instance has contained database authentication flag enabled', region, resource);
                        }
                } else {
                    helpers.addResult(results, 0, 
                        'SQL instance does not have any flags', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
