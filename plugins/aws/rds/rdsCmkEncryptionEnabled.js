var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS CMK Encryption',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures RDS instances are encrypted with KMS Customer Master Keys(CMKs).',
    more_info: 'RDS instances should be encrypted with Customer Master Keys in order to have full control over data encryption and decryption.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with KMS CMK encryption enabled.',
    apis: ['RDS:describeDBInstances', 'KMS:listAliases'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query for RDS DB instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS DB instance found', region);
                return rcb();
            }

            var listAliases = helpers.addSource(cache, source,
                ['kms', 'listAliases', region]);

            if (!listAliases || listAliases.err || !listAliases.data) {
                helpers.addResult(results, 3,
                    `Unable to query for KMS aliases: ${helpers.addError(listAliases)}`,
                    region);
                return rcb();
            }

            var aliasId;
            var kmsAliases = {};
            listAliases.data.forEach(function(alias){
                aliasId = alias.AliasArn.replace(/:alias\/.*/, ':key/' + alias.TargetKeyId);
                kmsAliases[aliasId] = alias.AliasName;
            });

            for (var i in describeDBInstances.data) {
                var db = describeDBInstances.data[i];
                var dbResource = db.DBInstanceArn;

                if (db.StorageEncrypted && db.KmsKeyId) {
                    if (kmsAliases[db.KmsKeyId]) {
                        if (kmsAliases[db.KmsKeyId] === 'alias/aws/rds'){
                            helpers.addResult(results, 2,
                                `RDS DB instance "${db.DBInstanceIdentifier}" is not using Customer Master Key for encryption`,
                                region, dbResource);
                        } else {
                            helpers.addResult(results, 0,
                                `RDS DB instance "${db.DBInstanceIdentifier}" is using Customer Master Key for encryption`,
                                region, dbResource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            `RDS DB instance encryption key "${db.KmsKeyId}" not found`,
                            region, dbResource);
                    }
                } else {
                    helpers.addResult(results, 2,
                        `RDS instance "${db.DBInstanceIdentifier}" does not have encryption at rest enabled`,
                        region, dbResource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
