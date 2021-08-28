var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Volume Groups Restorable',
    category: 'Block Storage',
    domain: 'Storage',
    description: 'Ensures volume groups can be restored to a recent point.',
    more_info: 'Enabling volume groups backups ensures that the volume group can be restored following in the event of data loss.',
    recommended_action: 'Ensure volume groups can be restored to a recent point.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/volumegroups.htm',
    apis: ['volumeGroup:list','volumeGroupBackup:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.volumeGroup, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var volumeGroups = helpers.addSource(cache, source,
                    ['volumeGroup', 'list', region]);

                if (!volumeGroups) return rcb();

                if (volumeGroups.err || !volumeGroups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for volume groups: ' + helpers.addError(volumeGroups), region);
                    return rcb();
                }

                if (!volumeGroups.data.length) {
                    helpers.addResult(results, 0, 'No volume groups found', region);
                    return rcb();
                }

                var volumeGroupBackups = helpers.addSource(cache, source,
                    ['volumeGroupBackup', 'list', region]);

                if (!volumeGroupBackups || volumeGroupBackups.err || !volumeGroupBackups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for volume group backups: ' + helpers.addError(volumeGroupBackups), region);
                    return rcb();
                }

                var enabledVolumeGroups = [];
                volumeGroupBackups.data.forEach(volumeGroupBackup => {
                    if (volumeGroupBackup.lifecycleState &&
                        volumeGroupBackup.lifecycleState.toUpperCase() === 'AVAILABLE') {
                        enabledVolumeGroups.push(volumeGroupBackup.volumeGroupId)
                    }
                });

                volumeGroups.data.forEach(volumeGroup => {
                    if (enabledVolumeGroups.indexOf(volumeGroup.id) > -1) {
                        helpers.addResult(results, 0,
                            'Volume group is actively restorable', region, volumeGroup.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Volume group is not actively restorable', region, volumeGroup.id);
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