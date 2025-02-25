/*********************
 Collector - The collector will query AWS APIs for the information required
 to run the CloudSploit scans. This data will be returned in the callback
 as a JSON object.

 Arguments:
 - AWSConfig: If using an access key/secret, pass in the config object. Pass null if not.
 - settings: custom settings for the scan. Properties:
 - skip_regions: (Optional) List of regions to skip
 - api_calls: (Optional) If provided, will only query these APIs.
 - Example:
 {
     "skip_regions": ["us-east-2", "eu-west-1"],
     "api_calls": ["EC2:describeInstances", "S3:listBuckets"]
 }
 - callback: Function to call when the collection is complete
 *********************/

var AWS = require('aws-sdk');
var async = require('async');
var https = require('https');
var helpers = require(__dirname + '/../../helpers/aws');
var collectors = require(__dirname + '/../../collectors/aws');
var collectData = require(__dirname + '/../../helpers/shared.js');

// Override max sockets
var agent = new https.Agent({maxSockets: 100});
AWS.config.update({httpOptions: {agent: agent}});

var CALLS_CONFIG = {
    TOTAL_PARTS: 14,
    CALLS_PARTS: 4,
    POSTCALLS_PARTS: 10
};

var rateError = {message: 'rate', statusCode: 429};

var apiRetryAttempts = 2;
var apiRetryBackoff = 500;
var apiRetryCap = 1000;
var hasReturned = false;

// Loop through all of the top-level collectors for each service
var collect = function(AWSConfig, settings, callback) {
    // Used to set locally the position of the calls to be
    // used in the calls or postcalls array
    let callsPart = 0;
    let apiCallErrors = 0;
    let apiCallTypeErrors = 0;
    let totalApiCallErrors = 0;

    // Used to track rate limiting retries
    let retries = [];

    // Used to gather info only
    if (settings.gather) {
        return callback(null, helpers.callsMultipart, helpers.postcallsMultipart);
    }

    // Configure an opt-in debug logger
    var AWSXRay;
    var debugMode = settings.debug_mode;
    if (debugMode) AWSXRay = require('aws-xray-sdk');

    AWSConfig.maxRetries = 8;
    AWSConfig.retryDelayOptions = {base: 100};

    var regions = helpers.regions(settings);

    var collection = {};
    var errors = {};
    var errorSummary = {};
    var errorTypeSummary = {};

    if (settings.collection) {
        collection = settings.collection;
    }

    callsPart = settings.part - 1;

    let runApiCalls = [];

    var AWSEC2 = new AWS.EC2(AWSConfig);
    var params = {AllRegions: true};
    var excludeRegions = [];
    var timeoutCheck;

    AWSEC2.describeRegions(params, function(err, accountRegions) {
        if (err) {
            console.log(`[INFO][REGIONS] Could not load all regions from EC2: ${JSON.stringify(err)}`);
        } else {
            if (accountRegions &&
                accountRegions.Regions) {
                excludeRegions = accountRegions.Regions.filter(region => {
                    return region.OptInStatus == 'not-opted-in';
                });
            }
        }
        if (settings.context && settings.context.getRemainingTimeInMillis) {
            timeoutCheck = setInterval(function(){
                if (process.env['LOCAL']) return 37000;

                if (settings.context.getRemainingTimeInMillis() < 15000) {
                    clearInterval(timeoutCheck);
                    hasReturned = true;
                    return callback(null, collection, runApiCalls, errorSummary, errorTypeSummary, errors, retries);
                }
            }, 4000);
        }
        async.eachOfLimit(helpers.callsMultipart[callsPart], 10, function(call, service, serviceCb) {
            if (callsPart >= CALLS_CONFIG.CALLS_PARTS) return serviceCb();
            var serviceName = service;
            var serviceLower = service.toLowerCase();
            if (!collection[serviceLower]) collection[serviceLower] = {};

            // Log service being processed
            console.log(`[INFO] Processing service: ${serviceName}`);

            // Loop through each of the service's functions
            async.eachOfLimit(call, 15, function(callObj, callKey, callCb) {
                if (settings.api_calls && settings.api_calls.indexOf(serviceName + ':' + callKey) === -1) return callCb();

                runApiCalls.push(serviceName + ':' + callKey);

                if (!collection[serviceLower][callKey]) {
                    collection[serviceLower][callKey] = {};
                    apiCallErrors = 0;
                    apiCallTypeErrors = 0;
                }

                helpers.debugApiCalls(callKey, serviceName, debugMode);

                var callRegions;

                if (callObj.default) {
                    callRegions = regions.default;
                } else {
                    callRegions = regions[serviceLower];
                }

                async.eachLimit(callRegions, helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                    if (settings.skip_regions &&
                        settings.skip_regions.indexOf(region) > -1 &&
                        helpers.globalServicesMultipart.indexOf(serviceName) === -1) return regionCb();

                    if (excludeRegions &&
                        excludeRegions.filter(excluded=> {
                            if (excluded.RegionName == region) {
                                return true;
                            }
                        }).length){
                        return regionCb();
                    }

                    if (!collection[serviceLower][callKey][region]) collection[serviceLower][callKey][region] = {};

                    var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
                    LocalAWSConfig.region = region;

                    if (callObj.override) {
                        collectors[serviceLower][callKey](LocalAWSConfig, collection, retries, function() {
                            if (callObj.rateLimit) {
                                setTimeout(function() {
                                    regionCb();
                                }, callObj.rateLimit);
                            } else {
                                regionCb();
                            }
                        });
                    } else {
                        if (!AWS[serviceName]) {
                            console.error(`[ERROR] Service ${serviceName} does not exist in AWS SDK.`);
                            regionCb();
                            return;
                        }
                        var executor = debugMode ? (AWSXRay.captureAWSClient(new AWS[serviceName](LocalAWSConfig))) : new AWS[serviceName](LocalAWSConfig);
                        var paginating = false;
                        var executorCb = function(err, data) {
                            if (err) {
                                collection[serviceLower][callKey][region].err = err;
                                helpers.logError(serviceLower, callKey, region, err, errors, apiCallErrors, apiCallTypeErrors, totalApiCallErrors, errorSummary, errorTypeSummary, debugMode);
                            }

                            if (!data) return regionCb();
                            if (callObj.property && !data[callObj.property]) return regionCb();
                            if (callObj.secondProperty && !data[callObj.secondProperty]) return regionCb();

                            var dataToAdd = callObj.secondProperty ? data[callObj.property][callObj.secondProperty] : data[callObj.property] ? data[callObj.property] : data;

                            if (paginating) {
                                collection[serviceLower][callKey][region].data = collection[serviceLower][callKey][region].data.concat(dataToAdd);
                            } else {
                                collection[serviceLower][callKey][region].data = dataToAdd;
                            }

                            // If a "paginate" property is set, e.g. NextToken
                            var nextToken = callObj.paginate;
                            if (settings.paginate && nextToken && data[nextToken]) {
                                paginating = true;
                                var paginateProp = callObj.paginateReqProp ? callObj.paginateReqProp : nextToken;
                                return execute([paginateProp, data[nextToken]]);
                            }

                            regionCb();
                        };

                        function execute(nextTokens) { // eslint-disable-line no-inner-declarations
                            // Each region needs its own local copy of callObj.params
                            // so that the injection of the NextToken doesn't break other calls
                            var localParams = JSON.parse(JSON.stringify(callObj.params || {}));
                            if (nextTokens) localParams[nextTokens[0]] = nextTokens[1];
                            if (callObj.params || nextTokens) {
                                async.retry({
                                    times: apiRetryAttempts,
                                    interval: function(retryCount){
                                        let retryExponential = 3;
                                        let retryLeveler = 3;
                                        let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
                                        let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
                                        let retry_seconds = Math.round(retry_temp/retryLeveler + Math.random(0, retry_temp) * 5000);

                                        console.log(`Trying ${callKey} again in: ${retry_seconds / 1000} seconds`);
                                        retries.push({seconds: Math.round(retry_seconds/1000)});
                                        return retry_seconds;
                                    },
                                    errorFilter: function(err) {
                                        return helpers.collectRateError(err, rateError);
                                    }
                                }, function(cb) {
                                    executor[callKey](localParams, function(err, data) {
                                        return cb(err, data);
                                    });
                                }, function(err, data){
                                    executorCb(err, data);
                                });
                            } else {
                                async.retry({
                                    times: apiRetryAttempts,
                                    interval: function(retryCount){
                                        let retryExponential = 3;
                                        let retryLeveler = 3;
                                        let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
                                        let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
                                        let retry_seconds = Math.round(retry_temp/retryLeveler + Math.random(0, retry_temp) * 5000);

                                        console.log(`Trying ${callKey} again in: ${retry_seconds / 1000} seconds`);
                                        retries.push({seconds: Math.round(retry_seconds/1000)});
                                        return retry_seconds;
                                    },
                                    errorFilter: function(err) {
                                        return helpers.collectRateError(err, rateError);
                                    }
                                }, function(cb) {
                                    executor[callKey](function(err, data) {
                                        return cb(err, data);
                                    });
                                }, function(err, data){
                                    executorCb(err, data);
                                });
                            }
                        }
                        execute();
                    }
                }, function() {
                    helpers.debugApiCalls(callKey, serviceName, debugMode, true);
                    callCb();
                });
            }, function() {
                return serviceCb();
            });
        }, function() {
            // Now loop through the follow up calls
            if (settings.part > CALLS_CONFIG.CALLS_PARTS) {
                callsPart = settings.part - CALLS_CONFIG.CALLS_PARTS - 1;
            } else {
                if (timeoutCheck) {
                    clearInterval(timeoutCheck);
                }
                if (!hasReturned) {
                    return callback(null, collection, runApiCalls, errorSummary, errorTypeSummary, errors);
                }
            }

            async.eachOfLimit(helpers.postcallsMultipart[callsPart], 10, function(serviceObj, service, serviceCb) {
                var serviceName = service;
                var serviceLower = service.toLowerCase();
                var sendIntegration = helpers.postcallsMultipart[callsPart] && helpers.postcallsMultipart[callsPart][serviceName] && helpers.postcallsMultipart[callsPart][serviceName].sendIntegration ? helpers.postcallsMultipart[callsPart][serviceName].sendIntegration : false;
                var serviceIntegration = {
                    enabled : sendIntegration && sendIntegration.enabled ? true : false,
                    sendLast : sendIntegration && sendIntegration.sendLast ? true : false
                };

                if (!collection[serviceLower]) collection[serviceLower] = {};

                // Log service being processed
                console.log(`[INFO] Processing service: ${serviceName}`);

                async.eachOfLimit(serviceObj, 1, function(callObj, callKey, callCb) {
                    if (settings.api_calls && settings.api_calls.indexOf(serviceName + ':' + callKey) === -1) return callCb();

                    runApiCalls.push(serviceName + ':' + callKey);

                    if (!collection[serviceLower][callKey]) {
                        collection[serviceLower][callKey] = {};
                        apiCallErrors = 0;
                        apiCallTypeErrors = 0;
                    }

                    helpers.debugApiCalls(callKey, serviceName, debugMode);

                    async.eachLimit(regions[serviceLower], helpers.MAX_REGIONS_AT_A_TIME, function(region, regionCb) {
                        if (settings.skip_regions &&
                            settings.skip_regions.indexOf(region) > -1 &&
                            helpers.globalServices.indexOf(serviceName) === -1) return regionCb();

                        if (excludeRegions &&
                            excludeRegions.filter(excluded=> {
                                if (excluded.RegionName == region) {
                                    return true;
                                }
                            }).length){
                            return regionCb();
                        }

                        if (!collection[serviceLower][callKey][region]) collection[serviceLower][callKey][region] = {};

                        // Ensure pre-requisites are met
                        if (callObj.reliesOnService && !collection[callObj.reliesOnService]) return regionCb();

                        if (callObj.reliesOnCall &&
                            (!collection[callObj.reliesOnService] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][region] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][region].data.length))
                            return regionCb();

                        var LocalAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
                        if (callObj.deleteRegion) {
                            //delete LocalAWSConfig.region;
                            LocalAWSConfig.region = settings.govcloud ? 'us-gov-west-1' : settings.china ? 'cn-north-1' : 'us-east-1';
                        } else {
                            LocalAWSConfig.region = region;
                        }
                        if (callObj.signatureVersion) LocalAWSConfig.signatureVersion = callObj.signatureVersion;

                        if (callObj.override) {
                            collectors[serviceLower][callKey](LocalAWSConfig, collection, retries, function() {

                                if (callObj.rateLimit) {
                                    setTimeout(function() {
                                        regionCb();
                                    }, callObj.rateLimit);
                                } else {
                                    regionCb();
                                }
                            });
                        } else {
                            if (!AWS[serviceName]) {
                                console.error(`[ERROR] Service ${serviceName} does not exist in AWS SDK.`);
                                regionCb();
                                return;
                            }
                            var executor = debugMode ? (AWSXRay.captureAWSClient(new AWS[serviceName](LocalAWSConfig))) : new AWS[serviceName](LocalAWSConfig);

                            if (!collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region] ||
                                !collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region].data) {
                                return regionCb();
                            }

                            async.eachLimit(collection[callObj.reliesOnService][callObj.reliesOnCall][LocalAWSConfig.region].data, 10, function(dep, depCb) {
                                collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]] = {};

                                var filter = {};
                                filter[callObj.filterKey] = dep[callObj.filterValue];

                                async.retry({
                                    times: apiRetryAttempts,
                                    interval: function(retryCount){
                                        let retryExponential = 3;
                                        let retryLeveler = 3;
                                        let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
                                        let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
                                        let retry_seconds = Math.round(retry_temp/retryLeveler + Math.random(0, retry_temp) * 5000);

                                        console.log(`Trying ${callKey} again in: ${retry_seconds / 1000} seconds`);
                                        retries.push({seconds: Math.round(retry_seconds/1000)});
                                        return retry_seconds;
                                    },
                                    errorFilter: function(err) {
                                        return helpers.collectRateError(err, rateError);
                                    }
                                }, function(cb) {
                                    executor[callKey](filter, function(err, data) {
                                        if (helpers.collectRateError(err, rateError)) {
                                            return cb(err);
                                        } else if (err) {
                                            collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].err = err;
                                            helpers.logError(serviceLower, callKey, region, err, errors, apiCallErrors, apiCallTypeErrors, totalApiCallErrors, errorSummary, errorTypeSummary, debugMode);
                                            return cb();
                                        } else {
                                            collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].data = data;
                                            return cb();
                                        }
                                    });
                                }, function(err){
                                    if (err) collection[serviceLower][callKey][LocalAWSConfig.region][dep[callObj.filterValue]].err = err;

                                    if (callObj.rateLimit) {
                                        setTimeout(function() {
                                            depCb();
                                        }, callObj.rateLimit);
                                    } else {
                                        depCb();
                                    }
                                });
                            }, function() {
                                regionCb();
                            });
                        }
                    }, function() {
                        helpers.debugApiCalls(callKey, serviceName, debugMode, true);
                        callCb();
                    });
                }, function() {
                    // Note: We intentionally verify against the full api calls and postcalls array below instead of the multipart
                    if (serviceIntegration.enabled &&
                        !serviceIntegration.sendLast &&
                        settings.identifier &&
                        collection[serviceLower] &&
                        Object.keys(collection[serviceLower]) &&
                        Object.keys(collection[serviceLower]).length &&
                        collectData.callsCollected(serviceName, collection, helpers.calls, helpers.postcalls)) {
                        collectData.processIntegration(serviceName, settings, collection, helpers.calls, helpers.postcalls, debugMode, function() {
                            return serviceCb();
                        });
                    } else {
                        return serviceCb();
                    }
                });
            }, function() {
                if (settings.identifier &&
                    settings.part == CALLS_CONFIG.TOTAL_PARTS) {
                    for (let serv of helpers.integrationSendLast) {
                        settings.identifier.service = serv.toLowerCase();

                        if (collection[serv.toLowerCase()] &&
                            Object.keys(collection[serv.toLowerCase()]) &&
                            Object.keys(collection[serv.toLowerCase()]).length &&
                            collectData.callsCollected(serv, collection, helpers.calls, helpers.postcalls)
                        ) {
                            collectData.processIntegration(serv, settings, collection, helpers.calls, helpers.postcalls, debugMode, function() {
                                console.log(`Integration for service ${serv} processed.`);
                            });
                        }
                    }
                }
                if (timeoutCheck) {
                    clearInterval(timeoutCheck);
                }
                if (!hasReturned) {
                    callback(null, collection, runApiCalls, errorSummary, errorTypeSummary, errors, retries);
                }
            });
        });
    });
};

module.exports = {
    collect: collect,
    calls: helpers.callsMultipart,
    postcalls: helpers.postcallsMultipart
};