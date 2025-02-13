var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Amazon Comprehend Flywheel In VPC',
    category: 'AI & ML',
    owasp: ['LLM07', 'LLM04', 'LLM02'],
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that an Amazon Comprehend Flywheel is configured with a VPC.',
    more_info: 'Configuring Amazon Comprehend flywheel within a VPC, establishes a secure environment that prevents unauthorized access to your data stored in job containers, minimizing the risk of internet exposure, data breaches and ensuring compliance with security standards.',
    recommended_action: 'Update Comprehend Flywheel and configure it within VPC.',
    link: 'https://docs.aws.amazon.com/comprehend/latest/dg/usingVPC.html',
    apis: ['Comprehend:listFlywheels', 'Comprehend:describeFlywheel'],
    realtime_triggers: ['comprehend:CreateFlywheel','comprehend:UpdateFlywheel','comprehend:DeleteFlywheel'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.comprehend, function(region, rcb){
            var listFlywheels = helpers.addSource(cache, source,
                ['comprehend', 'listFlywheels', region]);

            if (!listFlywheels) return rcb();

            if (listFlywheels.err || !listFlywheels.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Comprehend flywheels: ${helpers.addError(listFlywheels)}`, region);
                return rcb();
            }

            if (!listFlywheels.data.length) {
                helpers.addResult(results, 0, 'No existing Comprehend flywheels found', region);
                return rcb();
            }

            for (let flywheel of listFlywheels.data) {
                if (!flywheel.FlywheelArn) continue;
              
                let resource = flywheel.FlywheelArn;

                let describeFlywheel = helpers.addSource(cache, source,
                    ['comprehend', 'describeFlywheel', region, flywheel.FlywheelArn]);

                if (!describeFlywheel || describeFlywheel.err || !describeFlywheel.data || !describeFlywheel.data.FlywheelProperties) {
                    helpers.addResult(results, 3, `Unable to describe Comprehend flywheel: ${helpers.addError(describeFlywheel)}`, region, resource);
                    continue;
                }

                if (describeFlywheel.data.FlywheelProperties.DataSecurityConfig && describeFlywheel.data.FlywheelProperties.DataSecurityConfig.VpcConfig) {
                    helpers.addResult(results, 0,
                        'Comprehend flywheel is configured within a VPC', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Comprehend flywheel is not configured within a VPC', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};