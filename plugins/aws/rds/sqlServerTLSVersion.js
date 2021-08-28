var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SQL Server TLS Version',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures RDS SQL Servers do not allow outdated TLS certificate versions',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to RDS. A parameter group can be used to enforce this connection type.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/07/amazon-rds-for-sql-server-supports-disabling-old-versions-of-tls-and-ciphers/',
    recommended_action: 'Create a parameter group that contains the TLS version restriction and limit access to TLS 1.2 or higher',
    apis: ['RDS:describeDBParameterGroups', 'RDS:describeDBParameters'],
    remediation_description: 'TLS 1.2 will be enabled, TLS 1.0 and TLS 1.1 will be disabled',
    remediation_min_version: '202012181130',
    apis_remediate: ['RDS:describeDBParameterGroups'],
    actions: {
        remediate: ['RDS:modifyDBParameterGroup'],
        rollback: ['RDS:modifyDBParameterGroup']
    },
    permissions: {
        remediate: ['rds:ModifyDBParameterGroup'],
        rollback: ['rds:ModifyDBParameterGroup']
    },
    realtime_triggers: ['rds:CreateDBParameterGroup', 'rds:ModifyDBParameterGroup'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        async.each(regions.rds, function(region, rcb){
            var describeDBParameterGroups = helpers.addSource(cache, source,
                ['rds', 'describeDBParameterGroups', region]);

            if (!describeDBParameterGroups) return rcb();
            
            if (describeDBParameterGroups.err || !describeDBParameterGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for parameter groups: ' + helpers.addError(describeDBParameterGroups), region);
                return rcb();
            }

            if (!describeDBParameterGroups.data.length) {
                helpers.addResult(results, 0, 'No parameter groups found', region);
                return rcb();
            }

            var sqlFound = false;

            async.each(describeDBParameterGroups.data, function(group, paramcb){
                if (!group.DBParameterGroupName) return paramcb();
                
                var resource = group.DBParameterGroupArn;

                if (group.DBParameterGroupFamily &&
                    (!group.DBParameterGroupFamily.startsWith('sqlserver') ||
                    group.DBParameterGroupName.startsWith('default.'))) return paramcb();
                sqlFound = true;
                
                var parameters = helpers.addSource(cache, source,
                    ['rds', 'describeDBParameters', region, group.DBParameterGroupName]);

                if (!parameters || parameters.err || !parameters.data || !parameters.data.Parameters){
                    helpers.addResult(results, 3,
                        'Unable to query for parameters: ' + helpers.addError(parameters),
                        region, resource);
                    return paramcb();
                }

                var tls10;
                var tls11;
                var tls12;

                for (var param in parameters.data.Parameters) {
                    if (parameters.data.Parameters[param] &&
                        parameters.data.Parameters[param].ParameterName &&
                        parameters.data.Parameters[param].ParameterName === 'rds.tls10') {
                        tls10 = parameters.data.Parameters[param].ParameterValue;
                    } else if (parameters.data.Parameters[param] &&
                        parameters.data.Parameters[param].ParameterName &&
                        parameters.data.Parameters[param].ParameterName === 'rds.tls11') {
                        tls11 = parameters.data.Parameters[param].ParameterValue;
                    } else if (parameters.data.Parameters[param] &&
                        parameters.data.Parameters[param].ParameterName &&
                        parameters.data.Parameters[param].ParameterName === 'rds.tls12') {
                        tls12 = parameters.data.Parameters[param].ParameterValue;
                    }
                    if (!tls10 || !tls11 || !tls12) continue;
                }

                if (tls10 === 'disabled' && tls11 === 'disabled' && tls12 != 'disabled') {
                    helpers.addResult(results, 0,
                        'DB parameter group ' + (group.DBParameterGroupName) + ' uses TLS 1.2',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'DB parameter group ' + (group.DBParameterGroupName) + ' does not require TLS 1.2',
                        region, resource);
                }

                paramcb();
            });

            if (!sqlFound) {
                helpers.addResult(results, 0, 'No DB parameter groups for SQL servers found', region);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var putCall = this.actions.remediate;
        var pluginName = 'sqlServerTLSVersion';
        var pgNameArr = resource.split(':');
        var pgName = pgNameArr[pgNameArr.length - 1];

        var pgLocation = pgNameArr[3];

        // add the location of the parameter group to the config
        config.region = pgLocation;
        var params = {};

        // create the params necessary for the remediation
        
        params = {
            'DBParameterGroupName': pgName,
            'Parameters': [
                {
                    'ApplyMethod': 'pending-reboot',
                    'ParameterName': 'rds.tls10',
                    'ParameterValue': 'disabled'
                },
                {
                    'ApplyMethod': 'pending-reboot',
                    'ParameterName': 'rds.tls11',
                    'ParameterValue': 'disabled'
                }
            ]
        };

        var remediation_file = settings.remediation_file;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = {
            'TLS1.2': 'Disabled',
            'ParameterGroup': resource
        };

        // passes the config, put call, and params to the remediate helper function
        helpers.remediatePlugin(config, putCall[0], params, function(err) {
            if (err) {
                remediation_file['remediate']['actions'][pluginName]['error'] = err;
                return callback(err, null);
            }

            let action = params;
            action.action = putCall;

            remediation_file['post_remediate']['actions'][pluginName][resource] = action;
            remediation_file['remediate']['actions'][pluginName][resource] = {
                'Action': 'TLS1.2ENABLED',
                'ParameterGroup': pgName
            };
            
            settings.remediation_file = remediation_file;
            return callback(null, action);
        });
    }
};
