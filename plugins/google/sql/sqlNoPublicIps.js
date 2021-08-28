var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL No Public IPs',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that SQL instances are using private IPs instead of public IPs.',
    more_info: 'Cloud SQL databases should always use private IP addresses which provide improved network security and lower latency.',
    link: 'https://cloud.google.com/sql/docs/mysql/configure-private-ip',
    recommended_action: 'Make sure that SQL databases IP addresses setting does not have IP address of PRIMARY type',
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
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === "READ_REPLICA_INSTANCE") return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.ipAddresses &&
                    sqlInstance.ipAddresses.length) {
                    let found = sqlInstance.ipAddresses.find(address => address.type.toUpperCase() == 'PRIMARY');

                    if (found) {
                        helpers.addResult(results, 2, 
                            'SQL instance has public IPs', region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'SQL instance does not have public IPs', region, resource);
                    }
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have public IPs', region, resource);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
} 
