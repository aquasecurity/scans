var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Storage Auto Increase Enabled',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that Cloud SQL DB instances have Automatic Storage Increase feature enabled and desired limit is set for storage increases.',
    more_info: 'When this feature is enabled, Cloud SQL checks your available storage every 30 seconds. If the available storage falls below a threshold size, ' +
        'Cloud SQL automatically and permanently adds additional storage capacity. Setting a limit for automatic storage increase can prevent your instance size from growing too large.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings?authuser=1#automatic-storage-increase-2ndgen',
    recommended_action: 'Edit Cloud SQL instances and enable automatic storage increases feature under storage',
    apis: ['instances:sql:list', 'projects:get'],
    settings: {
        sql_storage_auto_increase_limit: {
            name: 'SQL Storage Auto Increase Limit',
            description: 'Maximum limit (GBs) of automatic storage increase for SQL instances. Should be between 100 and 30720. ' +
                'Setting this value zero, the default value, means that there is no limit',
            regex: '^.*$',
            default: '0'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            maxLimit: parseInt(settings.sql_storage_auto_increase_limit || this.settings.sql_storage_auto_increase_limit.default)
        };

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

                if (sqlInstance.settings &&
                    sqlInstance.settings.storageAutoResize) {
                    let resizeLimit = (sqlInstance.settings.storageAutoResizeLimit) ? parseInt(sqlInstance.settings.storageAutoResizeLimit) : 0;
                    if (resizeLimit <= config.maxLimit) {
                        helpers.addResult(results, 0,
                            `SQL instance automatic storage increase limit is ${resizeLimit} which is less than or equal to ${config.maxLimit}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `SQL instance automatic storage increase limit is ${resizeLimit} which is greater than ${config.maxLimit}`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        'SQL instance has automatic storage increase disabled', region, resource);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
} 
