var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Max Connections',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that max_connections is configured with optimal value for PostgreSQL instances.',
    more_info: 'An optimal value should be set for max_connections (maximum number of client connections) to meet the database workload requirements. ' +
        'If this no value is set for max_connections flag, instance assumes default value which is calculated per instance memory size.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag',
    recommended_action: 'Ensure that all PostgreSQL database instances have log_checkpoints flag and it value is set to on.',
    apis: ['instances:sql:list', 'projects:get'],
    settings: {
        min_postgres_max_connections: {
            name: 'Minimum PostgreSQL Max Connections',
            description: 'Minimum value set for max_connections flag',
            regex: '^.*$',
            default: ''
        },
        allow_default_max_connections_value: {
            name: 'Allow Default Max Connections Value',
            description: 'True or false, whether to allow PostgreSQL instances to use default value for max_connections flag. '+
                'This setting is checked only when max_connections flag value is not set',
            regex: '^(true|false)$',
            default: 'true'
        }
    },

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

        var config = {
            maxConnections: settings.min_postgres_max_connections || this.settings.min_postgres_max_connections.default,
            allow_default: settings.allow_default_max_connections_value || this.settings.allow_default_max_connections_value.default
        };

        if (!config.maxConnections.length) return callback(null, results, source);

        config.maxConnections = parseInt(config.maxConnections);
        config.allow_default = (config.allow_default == 'true');

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
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() == "READ_REPLICA_INSTANCE") return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toUpperCase().startsWith('POSTGRES')) {
                    helpers.addResult(results, 0, 'SQL instance database version is not of PostgreSQL type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'max_connections')) {
                    let maxConnectionsFlag = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'max_connections') || {};
                    let maxConnections = parseInt(maxConnectionsFlag.value || 0);
                    if (maxConnections >= config.maxConnections) {
                        helpers.addResult(results, 0,
                            `PostgreSQL instance max_connection value is ${maxConnections} which is greater than or equal to ${config.maxConnections}`, region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `PostgreSQL instance max_connection value is ${maxConnections} which is les than ${config.maxConnections}`, region, resource);
                    }
                } else {
                    if (config.allow_default) {
                        helpers.addResult(results, 0,
                            'PostgreSQL instance does not have max_connections value set and is using default value', region, resource);    
                    } else {
                        helpers.addResult(results, 2,
                            'PostgreSQL instance does not have max_connections value set and is using default value', region, resource);
                    }
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
