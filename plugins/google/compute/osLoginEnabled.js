var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'OS Login Enabled',
    category: 'Compute',
    description: 'Ensure OS login is enabled for a project.',
    more_info: 'Enabling OS login ensures that SSH keys used to connect to instances are mapped with IAM users.',
    link: 'https://cloud.google.com/compute/docs/instances/managing-instance-access',
    recommended_action: 'Set enable-oslogin in project-wide metadata so that it applies to all of the instances in the project.',
    apis: ['projects:get'],

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
                    'Unable to query for projects: ' + helpers.addError(projects), region);
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
                     return rcb();
                 }

                 let isEnabled = false;

                 metaData.items.forEach(item => {
                     if (item.key.toLowerCase() === 'enable-oslogin' &&
                         item.value.toLowerCase() === 'true') {
                         isEnabled = true;
                     }
                 });

                 if (isEnabled === true) {
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