var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'OS Login Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures OS login is enabled for the project',
    more_info: 'Enabling OS login ensures that SSH keys used to connect to instances are mapped with IAM users.',
    link: 'https://cloud.google.com/compute/docs/instances/managing-instance-access',
    recommended_action: 'Set enable-oslogin in project-wide metadata so that it applies to all of the instances in the project.',
    apis: ['projects:get'],
    compliance: {
        pci: 'PCI recommends implementing additional security features for ' +
            'any required service. This includes using secured technologies ' +
            'such as SSH.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.projects, function(region, rcb){
            let projects = helpers.addSource(cache, source,
                ['projects','get', region]);

            if (!projects) return rcb();

            if (projects.err || !projects.data) {
                helpers.addResult(results, 3,
                    'Unable to query for projects: ' + helpers.addError(projects), region, null, null, projects.err);
                return rcb();
            }

            if (!projects.data.length) {
                helpers.addResult(results, 0, 'No projects found', region);
                return rcb();
            }

            projects.data.forEach(project => {
                var metaData = project.commonInstanceMetadata || null;

                if (!metaData || !metaData.items || !metaData.items.length) {
                    helpers.addResult(results, 0, 'OS login is enabled by default', region);
                    return;
                }

                let isEnabled = metaData.items.find(item => item.key && item.key.toLowerCase() === 'enable-oslogin' &&
                    item.value && item.value.toLowerCase() === 'true');

                if (isEnabled) {
                    helpers.addResult(results, 0, 'OS login is enabled', region);
                } else {
                    helpers.addResult(results, 2, 'OS login is disabled', region);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}