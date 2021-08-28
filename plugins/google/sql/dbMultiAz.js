var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DB Multiple AZ',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures that SQL instances have a failover replica to be cross-AZ for high availability',
    more_info: 'Creating SQL instances in with a single AZ creates a single point of failure for all systems relying on that database. All SQL instances should be created in multiple AZs to ensure proper failover.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: 'Ensure that all database instances have a DB replica enabled in a secondary AZ.',
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

                if (sqlInstance.failoverReplica &&
                    sqlInstance.failoverReplica.available) {
                    helpers.addResult(results, 0, 
                        'SQL instance has multi-AZ enabled', region, resource);
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have multi-AZ enabled', region, resource);
                }
            })

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}