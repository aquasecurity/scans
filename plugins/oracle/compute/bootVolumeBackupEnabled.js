var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Backup Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures boot volumes have a backup policy.',
    more_info: 'Enabling a boot volume backup policy ensures that the boot volumes can be restored in the event of a compromised system or hardware failure.',
    recommended_action: 'Ensure all boot volumes have a backup policy.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm',
    apis: ['bootVolume:list','volumeBackupPolicyAssignment:bootVolume'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bootVolume, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var bootVolumes = helpers.addSource(cache, source,
                    ['bootVolume', 'list', region]);

                if (!bootVolumes) return rcb();

                if (bootVolumes.err || !bootVolumes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for boot volume attachments: ' + helpers.addError(bootVolumes), region);
                    return rcb();
                }

                if (!bootVolumes.data.length) {
                    helpers.addResult(results, 0, 'No boot volumes found', region);
                    return rcb();
                }

                var bootVolumeBackupPolicies = helpers.addSource(cache, source,
                    ['volumeBackupPolicyAssignment', 'bootVolume', region]);

                if (!bootVolumeBackupPolicies || bootVolumeBackupPolicies.err || !bootVolumeBackupPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for boot volume backups: ' + helpers.addError(bootVolumeBackupPolicies), region);
                    return rcb();
                }

                if (!bootVolumes.data.length) {
                    helpers.addResult(results, 2, 'No boot volume backup policies found', region);
                    return rcb();
                }

                var enabledBootVolumes = [];

                bootVolumeBackupPolicies.data.forEach(bootVolumeBackupPolicy => {
                    enabledBootVolumes.push(bootVolumeBackupPolicy.bootVolumeId)
                });

                bootVolumes.data.forEach(bootVolume => {
                    if (enabledBootVolumes.indexOf(bootVolume.id) > -1) {
                        helpers.addResult(results, 0,
                            'The boot volume has backup policies enabled', region, bootVolume.id);
                    } else {
                        helpers.addResult(results, 2,
                            'The boot volume has backup policies disabled', region, bootVolume.id);
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