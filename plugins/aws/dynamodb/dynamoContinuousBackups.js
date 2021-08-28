var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DynamoDB Continuous Backups',
    category: 'DynamoDB',
    domain: 'Databases',
    description: 'Ensures that Amazon DynamoDB tables have continuous backups enabled.',
    more_info: 'DynamoDB tables should have Continuous Backups and Point-In-Time Recovery (PITR) features enabled to protect DynamoDB data against accidental data writes.',
    link: 'https://aws.amazon.com/blogs/aws/new-amazon-dynamodb-continuous-backups-and-point-in-time-recovery-pitr/',
    recommended_action: 'Enable Continuous Backups and Point-In-Time Recovery (PITR) features.',
    apis: ['DynamoDB:listTables', 'DynamoDB:describeContinuousBackups', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.dynamodb, function(region, rcb){
            var listTables = helpers.addSource(cache, source,
                ['dynamodb', 'listTables', region]);

            if (!listTables) return rcb();

            if (listTables.err || !listTables.data) {
                helpers.addResult(results, 3,
                    `Unable to query for DynamoDB tables: ${helpers.addError(listTables)}`, region);
                return rcb();
            }

            if (!listTables.data.length) {
                helpers.addResult(results, 0, 'No DynamoDB tables found', region);
                return rcb();
            }

            async.each(listTables.data, function(table, cb) {
                var resource = `arn:${awsOrGov}:dynamodb:${region}:${accountId}:table/${table}`;

                var describeContinuousBackups = helpers.addSource(cache, source,
                    ['dynamodb', 'describeContinuousBackups', region, table]);

                if (!describeContinuousBackups || describeContinuousBackups.err || !describeContinuousBackups.data ||
                    !describeContinuousBackups.data.ContinuousBackupsDescription) {
                    helpers.addResult(results, 3,
                        `Unable to describe DynamoDB table continuous backups: ${helpers.addError(describeContinuousBackups)}`,
                        region, resource);
                    return cb();
                }

                if (describeContinuousBackups.data.ContinuousBackupsDescription.ContinuousBackupsStatus &&
                    describeContinuousBackups.data.ContinuousBackupsDescription.ContinuousBackupsStatus === 'ENABLED' &&
                    describeContinuousBackups.data.ContinuousBackupsDescription.PointInTimeRecoveryDescription &&
                    describeContinuousBackups.data.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus &&
                    describeContinuousBackups.data.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus === 'ENABLED') {
                    helpers.addResult(results, 0,
                        `DynamoDB table "${table}" has continuous backups enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `DynamoDB table "${table}" does not have continuous backups enabled`,
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
