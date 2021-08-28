var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Snapshot Encryption',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensures encryption is enabled for RDS snapshots to ensure encryption of data at rest.',
    more_info: 'AWS provides encryption for RDS snapshots which should be enabled to ensure that all data at rest is encrypted.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    recommended_action: 'Copy the snapshot to a new snapshot that is encrypted and delete the old snapshot.',
    apis: ['RDS:describeDBSnapshots'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb){
            var describeDBSnapshots = helpers.addSource(cache, source,
                ['rds', 'describeDBSnapshots', region]);

            if (!describeDBSnapshots) return rcb();

            if (describeDBSnapshots.err || !describeDBSnapshots.data) {
                helpers.addResult(results, 3,
                    'Unable to query for RDS snapshots: ' + helpers.addError(describeDBSnapshots), region);
                return rcb();
            }

            if (!describeDBSnapshots.data.length) {
                helpers.addResult(results, 0, 'No RDS snapshots found', region);
                return rcb();
            }

            describeDBSnapshots.data.forEach(snapshot => {
                var dbResource = snapshot.DBSnapshotArn;

                if (snapshot.Encrypted) {
                    var kmsKey = snapshot.KmsKeyId || 'Unknown';
                    helpers.addResult(results, 0, 'Snapshot encryption is enabled via KMS key: ' + kmsKey, region, dbResource);
                } else {
                    helpers.addResult(results, 2, 'Snapshot encryption not enabled', region, dbResource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
