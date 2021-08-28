var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Restorable',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures boot volumes can be restored to a recent point.',
    more_info: 'Having an active backup ensures that the boot volumes can be restored in the event of a compromised system or hardware failure.',
    recommended_action: 'Ensures boot volumes can be restored to a recent point.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm',
    apis: ['bootVolume:list','bootVolumeBackup:list'],

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

                var bootVolumeBackups = helpers.addSource(cache, source,
                    ['bootVolumeBackup', 'list', region]);

                if (!bootVolumeBackups || bootVolumeBackups.err || !bootVolumeBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for boot volume backups: ' + helpers.addError(bootVolumeBackups), region);
                    return rcb();
                }

                if (!bootVolumes.data.length) {
                    helpers.addResult(results, 2, 'No boot volume backups found', region);
                    return rcb();
                }

                var enabledBootVolumes = [];
                bootVolumeBackups.data.forEach(bootVolumeBackup => {
                    enabledBootVolumes.push(bootVolumeBackup.bootVolumeId)
                });

                bootVolumes.data.forEach(bootVolume => {
                    if (enabledBootVolumes.indexOf(bootVolume.id) > -1) {
                        helpers.addResult(results, 0,
                            'The boot volume is actively restorable', region, bootVolume.id);
                    } else {
                        helpers.addResult(results, 2,
                            'The boot volume is not actively restorable', region, bootVolume.id);
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
