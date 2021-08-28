var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DB Automated Backups',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures automated backups are enabled for SQL instances',
    more_info: 'Google provides a simple method of backing up SQL instances at a regular interval. This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: 'Ensure that all database instances are configured with automatic backups enabled.',
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
                    sqlInstance.settings.backupConfiguration &&
                    sqlInstance.settings.backupConfiguration.enabled) {
                    helpers.addResult(results, 0, 
                        'Automated backups are enabled', region, resource);
                } else {
                    helpers.addResult(results, 2, 
                        'Automated backups are not enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}