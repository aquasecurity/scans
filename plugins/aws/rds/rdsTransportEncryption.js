var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Transport Encryption Enabled',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures RDS SQL Server instances have Transport Encryption enabled.',
    more_info: 'Parameter group associated with the RDS instance should have transport encryption enabled to handle encryption and decryption',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html',
    recommended_action: 'Update the parameter group associated with the RDS instance to have rds.force_ssl set to true',
    apis: ['RDS:describeDBInstances', 'RDS:describeDBParameters', 'RDS:describeDBParameterGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var parameterMappings = {
            'sqlserver-ex': 'rds.force_ssl',
            'sqlserver-ee': 'rds.force_ssl',
            'sqlserver-se': 'rds.force_ssl',
            'sqlserver-web': 'rds.force_ssl',
            'postgres': 'rds.force_ssl'
        };

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) {
                return rcb();
            }

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for RDS DB instances: ${helpers.addError(describeDBInstances)}`,
                    region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS DB instances found');
                return rcb();
            }

            async.each(describeDBInstances.data, function(db, cb){
                if (!db.DBInstanceArn || !db.Engine) return cb();

                var resource = db.DBInstanceArn;

                if (parameterMappings[db.Engine.toLowerCase()]) {
                    if (!db.DBParameterGroups || !db.DBParameterGroups.length) {
                        helpers.addResult(results, 0,
                            `RDS DB instance "${db.DBInstanceIdentifier}" does not have any parameter groups associated`,
                            region, resource);
                    }

                    var forceSslEnabled = false;
                    
                    for (var pg in db.DBParameterGroups) {
                        var dbParameterGroup = db.DBParameterGroups[pg];
                        var groupName = dbParameterGroup.DBParameterGroupName;

                        var parameters = helpers.addSource(cache, source,
                            ['rds', 'describeDBParameters', region, groupName]);
    
                        if (!parameters || parameters.err || !parameters.data) {
                            helpers.addResult(results, 3,
                                `Unable to query for parameters: ${helpers.addError(parameters)}`,
                                region, resource);
                            return cb();
                        }

                        if (!parameters.data.Parameters || !parameters.data.Parameters.length) {
                            helpers.addResult(results, 3,
                                `No parameters found for RDS parameter group "${groupName}"`,
                                region, resource);
                            return cb();
                        }

                        for (var param of parameters.data.Parameters) {
                            if (param.ParameterName && param.ParameterName === parameterMappings[db.Engine] &&
                                param.ParameterValue && param.ParameterValue !== '0') {
                                forceSslEnabled = true;
                                break;
                            }
                        }

                        if (forceSslEnabled) break;
                    }
                    
                    if (forceSslEnabled) {
                        helpers.addResult(results, 0,
                            `RDS DB instance "${db.DBInstanceIdentifier}" has transport encryption enabled`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `RDS DB instance "${db.DBInstanceIdentifier}" does not have transport encryption enabled`,
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 0,
                        `TLS Enforcement is not supported on the ${db.DBInstanceIdentifier} database with ${db.Engine} engine`,
                        region, resource);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};