var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Block Volume Backup Enabled',
    category: 'Block Storage',
    domain: 'Storage',
    description: 'Ensures block volumes have backups enabled.',
    more_info: 'Enabling block volume backup policies ensures that the block volume can be restored following in the event of data loss.',
    recommended_action: 'Enable backups on each block volume.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/blockvolumebackups.htm',
    apis: ['volume:list','volumeBackupPolicyAssignment:volume'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.volume, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var blockVolumes = helpers.addSource(cache, source,
                    ['volume', 'list', region]);

                var blockVolumeBackupPolicies = helpers.addSource(cache, source,
                    ['volumeBackupPolicyAssignment', 'volume', region]);

                if (!blockVolumes) return rcb();

                if (blockVolumes.err || !blockVolumes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for block volumes: ' + helpers.addError(blockVolumes), region);
                    return rcb();
                }

                if (!blockVolumes.data.length) {
                    helpers.addResult(results, 0, 'No block volumes found', region);
                    return rcb();
                }

                if (!blockVolumeBackupPolicies || blockVolumeBackupPolicies.err || !blockVolumeBackupPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for block volume backups: ' + helpers.addError(blockVolumeBackupPolicies), region);
                    return rcb();
                }

                var enabledBlockVolumes = [];
                blockVolumeBackupPolicies.data.forEach(blockVolumeBackupPolicy => {
                    enabledBlockVolumes.push(blockVolumeBackupPolicy.assetId)
                });

                blockVolumes.data.forEach(blockVolume => {
                    if (enabledBlockVolumes.indexOf(blockVolume.id) > -1) {
                        helpers.addResult(results, 0,
                            'Block volume has a backup policy enabled', region, blockVolume.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Block volume has a backup policy disabled', region, blockVolume.id);
                    }
                });
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
