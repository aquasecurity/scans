var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Service Limits',
    category: 'IAM',
    domain: 'Identity and Access Management',
    description: 'Determines if the number of resources is close to the per-account limit.',
    more_info: 'Google limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    link: 'https://cloud.google.com/resource-manager/docs/limits',
    recommended_action: 'Contact GCP support to increase the number of resources available',
    apis: ['projects:get'],
    settings: {
        service_limit_percentage_fail: {
            name: 'Service Limit Percentage Fail',
            description: 'Return a failing result when utilized services equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        service_limit_percentage_warn: {
            name: 'Service Limit Percentage Warn',
            description: 'Return a warning result when utilized services equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            service_limit_percentage_fail: settings.service_limit_percentage_fail || this.settings.service_limit_percentage_fail.default,
            service_limit_percentage_warn: settings.service_limit_percentage_warn || this.settings.service_limit_percentage_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.projects, function(region, rcb){
            let projects = helpers.addSource(cache, source, 
                ['projects', 'get', region]);

            if (!projects) return rcb();

            if (projects.err || !projects.data) {
                helpers.addResult(results, 3, 'Unable to query projects', region, null, null, projects.err);
                return rcb();
            };

            if (!projects.data.length) {
                helpers.addResult(results, 0, 'No projects found', region);
                return rcb();
            };

            projects.data.forEach(project => {
                var warnReturnMsg = `The following services are over the ${config.service_limit_percentage_warn}% limit: `;
                var failReturnMsg = `The following services are over the ${config.service_limit_percentage_fail}% limit: `;
                var warnTrigger = false;
                var failTrigger = false;

                project.quotas.forEach(quota => {
                    var percentage = Math.ceil((quota.usage / quota.limit)*100);

                    if (percentage >= config.service_limit_percentage_fail) {
                        failReturnMsg += `${quota.metric} has ${quota.usage} of ${quota.limit} resources, `
                        failTrigger = true
                    } else if (percentage >= config.service_limit_percentage_warn) {
                        warnReturnMsg += `${quota.metric} has ${quota.usage} of ${quota.limit} resources, `
                        warnTrigger = true;
                    };
                });

                if (warnTrigger) {
                    helpers.addResult(results, 1, warnReturnMsg, region, project.id, custom);
                };
                if (failTrigger) {
                    helpers.addResult(results, 2, failReturnMsg, region, project.id, custom);
                };
                if (!failTrigger && !warnTrigger) {
                    helpers.addResult(results, 0, 'All resources are within the service limits', region);
                };
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}