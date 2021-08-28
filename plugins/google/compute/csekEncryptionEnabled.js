var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CSEK Encryption Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures Customer Supplied Encryption Key Encryption is enabled on disks',
    more_info: 'Google encrypts all disks at rest by default. By using CSEK only the users with the key can access the disk. Anyone else, including Google, cannot access the disk data.',
    link: 'https://cloud.google.com/compute/docs/disks/customer-supplied-encryption',
    recommended_action: 'CSEK can only be configured when creating a disk. Delete the disk and redeploy with CSEK.',
    apis: ['disks:list', 'projects:get'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
            'Enabling encryption of disk data helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
            'Encryption should be enabled for all disks storing this ' +
            'type of data.'
    },
    settings: {
        disk_result_limit: {
            name: 'Compute Disks Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: '20',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            disk_result_limit: parseInt(settings.disk_result_limit || this.settings.disk_result_limit.default)
        };

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.disks, (region, rcb) => {
            var noDisks = [];
            var zones = regions.zones;
            var badDisks = [];
            var goodDisks = [];
            async.each(zones[region], function(zone, zcb) {
                var disks = helpers.addSource(cache, source,
                    ['disks', 'list', zone]);

                if (!disks) return zcb();

                if (disks.err || !disks.data) {
                    helpers.addResult(results, 3,
                        'Unable to query compute disks', region, null, null, disks.err);
                    return zcb();
                }

                if (!disks.data.length) {
                    noDisks.push(zone);
                    return zcb();
                }

                disks.data.forEach(disk => {
                    if (!disk.id) return;
                    if (disk.creationTimestamp &&
                        disk.diskEncryptionKey &&
                        Object.keys(disk.diskEncryptionKey) &&
                        Object.keys(disk.diskEncryptionKey).length) {
                        goodDisks.push(disk.id)
                    } else if (disk.creationTimestamp) {
                        badDisks.push(disk.id)
                    }
                });

                if (badDisks.length) {
                    if (badDisks.length > config.disk_result_limit) {
                        helpers.addResult(results, 2,
                            `CSEK Encryption is disabled for ${badDisks.length} disks`, region);
                    } else {
                        badDisks.forEach(disk=> {
                            let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                            helpers.addResult(results, 2,
                                `CSEK Encryption is disabled for disk`, region, resource);
                        });
                    }
                }
                if (goodDisks.length) {
                    if (goodDisks.length > config.disk_result_limit) {
                        helpers.addResult(results, 0,
                            `CSEK Encryption is enabled for ${goodDisks.length} disks`, region);
                    } else {
                        goodDisks.forEach(disk=> {
                            let resource = helpers.createResourceName('disks', disk, project, 'zone', zone);
                            helpers.addResult(results, 0,
                                `CSEK Encryption is enabled for disk`, region, resource);
                        });
                    }
                }
                if (!goodDisks.length && !badDisks.length) noDisks.push(zone);
                zcb();
            }, function(){
                if (noDisks.length) {
                    helpers.addResult(results, 0, `No compute disks found in following zones: ${noDisks.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};