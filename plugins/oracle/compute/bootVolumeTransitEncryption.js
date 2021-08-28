var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Boot Volume Transit Encryption',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures in-transit data encryption is enabled on boot volumes.',
    more_info: 'Enabling boot volume in-transit data encryption ensures that boot volume data is secured and follows Oracle security best practices.',
    recommended_action: 'boot volume transit encryption can only be configured when creating a new instance. Recreate the instance with in-transit encryption enabled.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Block/Concepts/bootvolumes.htm',
    apis: ['bootVolumeAttachment:list'],
    compliance: {
        pci: 'PCI requires strong cryptographic and security protocols ' +
            'when transmitting user data over open, public networks.',
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'boot volume transit encryption should be used.',
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.bootVolumeAttachment, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var bootVolumeAttachments = helpers.addSource(cache, source,
                    ['bootVolumeAttachment', 'list', region]);

                if (!bootVolumeAttachments) return rcb();

                if (bootVolumeAttachments.err || !bootVolumeAttachments.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for boot volume attachments: ' + helpers.addError(bootVolumeAttachments), region);
                    return rcb();
                }

                if (!bootVolumeAttachments.data.length) {
                    helpers.addResult(results, 0, 'No boot volume attachments found', region);
                    return rcb();
                }

                bootVolumeAttachments.data.forEach(bootVolumeAttachment => {
                    if (bootVolumeAttachment.isPvEncryptionInTransitEnabled) {
                        helpers.addResult(results, 0, 'boot volume transit encryption is enabled', region, bootVolumeAttachment.bootVolumeId);
                    } else {
                        helpers.addResult(results, 2, 'boot volume transit encryption is disabled', region, bootVolumeAttachment.bootVolumeId);
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