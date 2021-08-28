var async = require('async');
var helpers = require('../../../helpers/oracle/');

module.exports = {
    title: 'Instance Max Count',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures the total number of VM instances does not exceed a set threshold.',
    more_info: 'The number of running VM instances should be carefully audited, especially in unused regions, to ensure only approved applications are consuming compute resources. Many compromised Oracle accounts see large numbers of VM instances launched.',
    recommended_action: 'Ensure that the number of running VM instances matches the expected count. If instances are launched above the threshold, investigate to ensure they are legitimate.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/instancemanagement.htm',
    apis: ['instance:list'],
    settings: {
        instance_count_global_threshold: {
            name: 'Instance Count Global Threshold',
            description: 'Checks for the number of running instances across all regions and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_ashburn_1: {
            name: 'Instance Count Region Threshold: us-ashburn-1',
            description: 'Checks for the number of running instances in the us-ashburn-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_us_phoenix_1: {
            name: 'Instance Count Region Threshold: us-phoenix-1',
            description: 'Checks for the number of running instances in the us-phoenix-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_eu_frankfurt_1: {
            name: 'Instance Count Region Threshold: eu-frankfurt-1',
            description: 'Checks for the number of running instances in the eu-frankfurt-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_uk_london_1: {
            name: 'Instance Count Region Threshold: uk-london-1',
            description: 'Checks for the number of running instances in the uk-london-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ca_toronto_1: {
            name: 'Instance Count Region Threshold: ca-toronto-1',
            description: 'Checks for the number of running instances in the ca-toronto-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_mumbai_1: {
            name: 'Instance Count Region Threshold: ap-mumbai-1',
            description: 'Checks for the number of running instances in the ap-mumbai-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_seoul_1: {
            name: 'Instance Count Region Threshold: ap-seoul-1',
            description: 'Checks for the number of running instances in the ap-seoul-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_tokyo_1: {
            name: 'Instance Count Region Threshold: ap-tokyo-1',
            description: 'Checks for the number of running instances in the ap-tokyo-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_sydney_1: {
            name: 'Instance Count Region Threshold: ap-sydney-1',
            description: 'Checks for the number of running instances in the ap-sydney-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_sa_saopaulo_1: {
            name: 'Instance Count Region Threshold: sa-saopaulo-1',
            description: 'Checks for the number of running instances in the sa-saopaulo-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_osaka_1: {
            name: 'Instance Count Region Threshold: ap-osaka-1',
            description: 'Checks for the number of running instances in the ap-osaka-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_eu_zurich_1: {
            name: 'Instance Count Region Threshold: eu-zurich-1',
            description: 'Checks for the number of running instances in the eu-zurich-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_melbourne_1: {
            name: 'Instance Count Region Threshold: ap-melbourne-1',
            description: 'Checks for the number of running instances in the ap-melbourne-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_sa_vinhedo_1: {
            name: 'Instance Count Region Threshold: sa-vinhedo-1',
            description: 'Checks for the number of running instances in the sa-vinhedo-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ca_montreal_1: {
            name: 'Instance Count Region Threshold: ca-montreal-1',
            description: 'Checks for the number of running instances in the ca-montreal-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_sa_santiago_1: {
            name: 'Instance Count Region Threshold: sa-santiago-1',
            description: 'Checks for the number of running instances in the sa-santiago-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_hyderabad_1: {
            name: 'Instance Count Region Threshold: ap-hyderabad-1',
            description: 'Checks for the number of running instances in the ap-hyderabad-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_eu_amsterdam_1: {
            name: 'Instance Count Region Threshold: eu-amsterdam-1',
            description: 'Checks for the number of running instances in the eu-amsterdam-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_me_jeddah_1: {
            name: 'Instance Count Region Threshold: me-jeddah-1',
            description: 'Checks for the number of running instances in the me-jeddah-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_ap_chuncheon_1: {
            name: 'Instance Count Region Threshold: ap-chuncheon-1',
            description: 'Checks for the number of running instances in the ap-chuncheon-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_me_dubai_1: {
            name: 'Instance Count Region Threshold: me-dubai-1',
            description: 'Checks for the number of running instances in the me-dubai-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_uk_cardiff_1: {
            name: 'Instance Count Region Threshold: uk-cardiff-1',
            description: 'Checks for the number of running instances in the uk-cardiff-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        },
        instance_count_region_threshold_us_sanjose_1: {
            name: 'Instance Count Region Threshold: us-sanjose-1',
            description: 'Checks for the number of running instances in the us-sanjose-1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 50
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            instance_count_global_threshold: settings.instance_count_global_threshold || this.settings.instance_count_global_threshold.default,
            instance_count_region_threshold_us_ashburn_1: settings.instance_count_region_threshold_us_ashburn_1 || this.settings.instance_count_region_threshold_us_ashburn_1.default,
            instance_count_region_threshold_us_phoenix_1: settings.instance_count_region_threshold_us_phoenix_1 || this.settings.instance_count_region_threshold_us_phoenix_1.default,
            instance_count_region_threshold_eu_frankfurt_1: settings.instance_count_region_threshold_eu_frankfurt_1 || this.settings.instance_count_region_threshold_eu_frankfurt_1.default,
            instance_count_region_threshold_uk_london_1: settings.instance_count_region_threshold_uk_london_1 || this.settings.instance_count_region_threshold_uk_london_1.default,
            instance_count_region_threshold_ca_toronto_1: settings.instance_count_region_threshold_ca_toronto_1 || this.settings.instance_count_region_threshold_ca_toronto_1.default,
            instance_count_region_threshold_ap_mumbai_1: settings.instance_count_region_threshold_ap_mumbai_1 || this.settings.instance_count_region_threshold_ap_mumbai_1.default,
            instance_count_region_threshold_ap_seoul_1: settings.instance_count_region_threshold_ap_seoul_1 || this.settings.instance_count_region_threshold_ap_seoul_1.default,
            instance_count_region_threshold_ap_tokyo_1: settings.instance_count_region_threshold_ap_tokyo_1 || this.settings.instance_count_region_threshold_ap_tokyo_1.default,
            instance_count_region_threshold_ap_sydney_1: settings.instance_count_region_threshold_ap_sydney_1 || this.settings.instance_count_region_threshold_ap_sydney_1.default,
            instance_count_region_threshold_sa_saopaulo_1: settings.instance_count_region_threshold_sa_saopaulo_1 || this.settings.instance_count_region_threshold_sa_saopaulo_1.default,
            instance_count_region_threshold_ap_osaka_1: settings.instance_count_region_threshold_ap_osaka_1 || this.settings.instance_count_region_threshold_ap_osaka_1.default,
            instance_count_region_threshold_eu_zurich_1: settings.instance_count_region_threshold_eu_zurich_1 || this.settings.instance_count_region_threshold_eu_zurich_1.default,
            instance_count_region_threshold_ap_melbourne_1: settings.instance_count_region_threshold_ap_melbourne_1 || this.settings.instance_count_region_threshold_ap_melbourne_1.default,
            instance_count_region_threshold_sa_vinhedo_1: settings.instance_count_region_threshold_sa_vinhedo_1 || this.settings.instance_count_region_threshold_sa_vinhedo_1.default,
            instance_count_region_threshold_ca_montreal_1: settings.instance_count_region_threshold_ca_montreal_1 || this.settings.instance_count_region_threshold_ca_montreal_1.default,
            instance_count_region_threshold_sa_santiago_1: settings.instance_count_region_threshold_sa_santiago_1 || this.settings.instance_count_region_threshold_sa_santiago_1.default,
            instance_count_region_threshold_ap_hyderabad_1: settings.instance_count_region_threshold_ap_hyderabad_1 || this.settings.instance_count_region_threshold_ap_hyderabad_1.default,
            instance_count_region_threshold_eu_amsterdam_1: settings.instance_count_region_threshold_eu_amsterdam_1 || this.settings.instance_count_region_threshold_eu_amsterdam_1.default,
            instance_count_region_threshold_me_jeddah_1: settings.instance_count_region_threshold_me_jeddah_1 || this.settings.instance_count_region_threshold_me_jeddah_1.default,
            instance_count_region_threshold_ap_chuncheon_1: settings.instance_count_region_threshold_ap_chuncheon_1 || this.settings.instance_count_region_threshold_ap_chuncheon_1.default,
            instance_count_region_threshold_me_dubai_1: settings.instance_count_region_threshold_me_dubai_1 || this.settings.instance_count_region_threshold_me_dubai_1.default,
            instance_count_region_threshold_uk_cardiff_1: settings.instance_count_region_threshold_uk_cardiff_1 || this.settings.instance_count_region_threshold_uk_cardiff_1.default,
            instance_count_region_threshold_us_sanjose_1: settings.instance_count_region_threshold_us_sanjose_1 || this.settings.instance_count_region_threshold_us_sanjose_1.default
        };

        for (c in config) {
            if (settings.hasOwnProperty(c)) {
                config[c] = settings[c];
            }
        }

        var custom = helpers.isCustom(settings, this.settings);
        
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);
        var instanceCountGlobal = 0;

        async.each(regions.instance, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instances = helpers.addSource(cache, source,
                    ['instance', 'list', region]);

                if (!instances) return rcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instances: ' + helpers.addError(instances), region);
                    return rcb();
                }

                if (!instances.data.length) {
                    helpers.addResult(results, 0, 'No instances found', region);
                    return rcb();
                }

                var instanceCount = 0;

                instances.data.forEach(instance => {
                    if (instance.lifecycleState &&
                        instance.lifecycleState === 'RUNNING') {
                        instanceCountGlobal++;
                        instanceCount++;
                    }
                });

                var regionUnderscore = region.replace(/-/g, '_');
                var regionThreshold = config['instance_count_region_threshold_'+regionUnderscore];

                if (!regionThreshold) {
                    helpers.addResult(results, 3,
                        'The region: ' + region + ' does not have a maximum instances count setting.', region);
                } else if (instanceCount > regionThreshold) {
                    helpers.addResult(results, 2,
                        instanceCount + ' VM instances running in ' +
                        region + ' region, exceeding limit of: ' +
                        regionThreshold, region, null, custom);
                } else {
                    helpers.addResult(results, 0,
                        instanceCount + ' instances in the region are within the regional expected count of: ' + regionThreshold, region, null, custom);
                }
            }

            rcb();
        }, function(){
            // Global checking goes here
            var globalThreshold = config.instance_count_global_threshold;

            if (instanceCountGlobal > globalThreshold) {
                helpers.addResult(results, 2,
                instanceCountGlobal + ' VM instances running in all regions, exceeding limit of: ' + globalThreshold, null, null, custom);
            } else {
                helpers.addResult(results, 0,
                instanceCountGlobal + ' instances in the account are within the global expected count of: ' + globalThreshold, null, null, custom);
            }

            callback(null, results, source);
        });
    }
};