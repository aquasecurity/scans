var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VM Max Instances',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensures the total number of VM instances does not exceed a set threshold',
    more_info: 'The number of running VM instances should be carefully audited, especially in unused regions, to ensure only approved applications are consuming compute resources. Many compromised Google accounts see large numbers of VM instances launched.',
    link: 'https://cloud.google.com/compute/docs/instances/',
    recommended_action: 'Ensure that the number of running VM instances matches the expected count. If instances are launched above the threshold, investigate to ensure they are legitimate.',
    apis: ['instances:compute:list'],
    settings: {
        instance_count_global_threshold: {
            name: 'Instance Count Global Threshold',
            description: 'Checks for the number of running instances across all regions and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 200
        },
        instance_count_region_threshold_us_east1: {
            name: 'Instance Count Region Threshold: us-east1',
            description: 'Checks for the number of running instances in the us-east1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_east4: {
            name: 'Instance Count Region Threshold: us-east2',
            description: 'Checks for the number of running instances in the us-east2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_west1: {
            name: 'Instance Count Region Threshold: us-west1',
            description: 'Checks for the number of running instances in the us-west1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_west2: {
            name: 'Instance Count Region Threshold: us-west2',
            description: 'Checks for the number of running instances in the us-west2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_us_central1: {
            name: 'Instance Count Region Threshold: us-central1',
            description: 'Checks for the number of running instances in the us-central1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_northamerica_northeast1: {
            name: 'Instance Count Region Threshold: northamerica-northeast1',
            description: 'Checks for the number of running instances in the northamerica-northeast1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_southamerica_east1: {
            name: 'Instance Count Region Threshold: southamerica-east1',
            description: 'Checks for the number of running instances in the southamerica-east1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_west1: {
            name: 'Instance Count Region Threshold: europe-west1',
            description: 'Checks for the number of running instances in the europe-west1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_west2: {
            name: 'Instance Count Region Threshold: europe-west2',
            description: 'Checks for the number of running instances in the europe-west2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_west3: {
            name: 'Instance Count Region Threshold: europe-west3',
            description: 'Checks for the number of running instances in the europe-west3 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_west4: {
            name: 'Instance Count Region Threshold: europe-west4',
            description: 'Checks for the number of running instances in the europe-west4 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_west5: {
            name: 'Instance Count Region Threshold: europe-west5',
            description: 'Checks for the number of running instances in the europe-west5 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_west6: {
            name: 'Instance Count Region Threshold: europe-west6',
            description: 'Checks for the number of running instances in the europe-west6 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_europe_north1: {
            name: 'Instance Count Region Threshold: europe-north1',
            description: 'Checks for the number of running instances in the europe-north1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_asia_south1: {
            name: 'Instance Count Region Threshold: asia-south1',
            description: 'Checks for the number of running instances in the asia-south1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_asia_southeast1: {
            name: 'Instance Count Region Threshold: asia-southeast1',
            description: 'Checks for the number of running instances in the asia-southeast1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_asia_east1: {
            name: 'Instance Count Region Threshold: asia-east1',
            description: 'Checks for the number of running instances in the asia-east1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_asia_east2: {
            name: 'Instance Count Region Threshold: asia-east2',
            description: 'Checks for the number of running instances in the asia-east2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_asia_northeast1: {
            name: 'Instance Count Region Threshold: asia-northeast1',
            description: 'Checks for the number of running instances in the asia-northeast1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_asia_northeast2: {
            name: 'Instance Count Region Threshold: asia-northeast2',
            description: 'Checks for the number of running instances in the asia-northeast2 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },
        instance_count_region_threshold_australia_southeast1: {
            name: 'Instance Count Region Threshold: australia-southeast1',
            description: 'Checks for the number of running instances in the australia-southeast1 region and triggers a failing result if it exceeds the specified count',
            regex: '^[0-9]{1,4}$',
            default: 100
        },

    },

    run: function(cache, settings, callback) {
        var config = {
            instance_count_global_threshold: settings.instance_count_global_threshold || this.settings.instance_count_global_threshold.default,

            instance_count_region_threshold_us_east1: settings.instance_count_region_threshold_us_east1 || this.settings.instance_count_region_threshold_us_east1.default,

            instance_count_region_threshold_us_east4: settings.instance_count_region_threshold_us_east4 || this.settings.instance_count_region_threshold_us_east4.default,

            instance_count_region_threshold_us_west1: settings.instance_count_region_threshold_us_west1 || this.settings.instance_count_region_threshold_us_west1.default,

            instance_count_region_threshold_us_west2: settings.instance_count_region_threshold_us_west2 || this.settings.instance_count_region_threshold_us_west2.default,

            instance_count_region_threshold_us_central1: settings.instance_count_region_threshold_us_central1 || this.settings.instance_count_region_threshold_us_central1.default,

            instance_count_region_threshold_northamerica_northeast1: settings.instance_count_region_threshold_northamerica_northeast1 || this.settings.instance_count_region_threshold_northamerica_northeast1.default,

            instance_count_region_threshold_southamerica_east1: settings.instance_count_region_threshold_southamerica_east1 || this.settings.instance_count_region_threshold_southamerica_east1.default,

            instance_count_region_threshold_europe_west1: settings.instance_count_region_threshold_europe_west1 || this.settings.instance_count_region_threshold_europe_west1.default,

            instance_count_region_threshold_europe_west2: settings.instance_count_region_threshold_europe_west2 || this.settings.instance_count_region_threshold_europe_west2.default,

            instance_count_region_threshold_europe_west3: settings.instance_count_region_threshold_europe_west3 || this.settings.instance_count_region_threshold_europe_west3.default,

            instance_count_region_threshold_europe_west4: settings.instance_count_region_threshold_europe_west4 || this.settings.instance_count_region_threshold_europe_west4.default,

            instance_count_region_threshold_europe_west5: settings.instance_count_region_threshold_europe_west5 || this.settings.instance_count_region_threshold_europe_west5.default,

            instance_count_region_threshold_europe_west6: settings.instance_count_region_threshold_europe_west6 || this.settings.instance_count_region_threshold_europe_west6.default,

            instance_count_region_threshold_europe_north1: settings.instance_count_region_threshold_europe_north1 || this.settings.instance_count_region_threshold_europe_north1.default,

            instance_count_region_threshold_asia_south1: settings.instance_count_region_threshold_asia_south1 || this.settings.instance_count_region_threshold_asia_south1.default,

            instance_count_region_threshold_asia_southeast1: settings.instance_count_region_threshold_asia_southeast1 || this.settings.instance_count_region_threshold_asia_southeast1.default,

            instance_count_region_threshold_asia_east1: settings.instance_count_region_threshold_asia_east1 || this.settings.instance_count_region_threshold_asia_east1.default,

            instance_count_region_threshold_asia_east2: settings.instance_count_region_threshold_asia_east2 || this.settings.instance_count_region_threshold_asia_east2.default,

            instance_count_region_threshold_asia_northeast1: settings.instance_count_region_threshold_asia_northeast1 || this.settings.instance_count_region_threshold_asia_northeast1.default,

            instance_count_region_threshold_asia_northeast2: settings.instance_count_region_threshold_asia_northeast2 || this.settings.instance_count_region_threshold_asia_northeast2.default,

            instance_count_region_threshold_australia_southeast1: settings.instance_count_region_threshold_australia_southeast1 || this.settings.instance_count_region_threshold_australia_southeast1.default,


        };
        for (c in config) {
            if (settings.hasOwnProperty(c)) {
                config[c] = settings[c];
            }
        }

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions();
        var instanceCountGlobal = 0;

        async.each(regions.instances.compute, function(region, rcb){
            var zones = regions.zones;
            var instanceCount = 0;
            var myError = {};
            var noInstances = {};

            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    if (!myError[region]) {
                        myError[region] = [];
                    }
                    myError[region].push(zone);
                    myError[region][zone] = instances.err;
                    return zcb();
                }

                if (!instances.data.length) {
                    if (!noInstances[region]) {
                        noInstances[region] = [];
                    }
                    noInstances[region].push(zone);
                    return zcb();
                }
                instances.data.forEach(instance => {
                    if (instance.status && instance.status == "RUNNING") {
                        instanceCountGlobal +=1;
                        instanceCount +=1;
                    }
                });

                zcb();
            }, function() {
                // Print region results
                var regionUnderscore = region.replace(/-/g, '_');
                var regionThreshold = config['instance_count_region_threshold_'+regionUnderscore];

                if (myError[region] &&
                    zones[region] &&
                    (myError[region].join(',') === zones[region].join(','))) {
                    helpers.addResult(results, 3, 'Unable to query Instances', region, null, null, myError);

                } else if (noInstances[region] &&
                    zones[region] &&
                    (noInstances[region].join(',') === zones[region].join(','))) {
                    helpers.addResult(results, 0, 'No instances found in the region' , region);

                } else if (!regionThreshold) {
                    helpers.addResult(results, 3,
                        'The region: ' + region + ' does not have a maximum instances count setting.', region);
                } else if (instanceCount > regionThreshold) {
                    helpers.addResult(results, 2,
                        instanceCount + '  instances running in ' +
                        region + ' region, exceeding limit of: ' +
                        regionThreshold, region, null, custom);
                } else {
                    helpers.addResult(results, 0,
                        instanceCount + '  instances in the region are within the regional expected count of: ' + regionThreshold, region, null, custom);
                }
                rcb();
            });
        }, function() {
             // Print global results
             var globalThreshold = config.instance_count_global_threshold;

             if (instanceCountGlobal > globalThreshold) {
                 helpers.addResult(results, 2,
                     instanceCountGlobal + ' instances running in all regions, exceeding limit of: ' + globalThreshold, null, null, custom);
             } else {
                 helpers.addResult(results, 0,
                     instanceCountGlobal + ' instances in the account are within the global expected count of: ' + globalThreshold, null, null, custom);
             }
     
             callback(null, results, source); 
        });
    }
};
