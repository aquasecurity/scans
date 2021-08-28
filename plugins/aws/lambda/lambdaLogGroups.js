var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Log Groups',
    category: 'Lambda',
    domain: 'Serverless',
    description: 'Ensures each Lambda function has a valid log group attached to it',
    more_info: 'Every Lambda function created should automatically have a CloudWatch log group generated to handle its log streams.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html',
    recommended_action: 'Update the Lambda function permissions to allow CloudWatch logging.',
    apis: ['Lambda:listFunctions', 'CloudWatchLogs:describeLogGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            var describeLogGroups = helpers.addSource(cache, source,
                ['cloudwatchlogs', 'describeLogGroups', region]);

            for (var f in listFunctions.data) {
                var func = listFunctions.data[f];
                var arn = func.FunctionArn;

                var result = [0, ''];

                if (!describeLogGroups || describeLogGroups.err || !describeLogGroups.data) {
                    result = [3, 'Error querying for log groups: ' + helpers.addError(describeLogGroups)];
                } else if (describeLogGroups.data) {
                    var found = describeLogGroups.data.find(function(lg) {
                        return lg.logGroupName == '/aws/lambda/' + func.FunctionName;
                    });

                    if (found) {
                        result = [0, 'Function has log group: ' + found.logGroupName];
                    } else {
                        // check for lambda@edge log groups
                        var lambdaEdgeLogGroupName = '/aws/lambda/' + region + '.' + func.FunctionName;
                        for (var cloudwatchRegion of regions.cloudwatchlogs) {
                            var regionLogGroups = helpers.addSource(cache, source,
                                ['cloudwatchlogs', 'describeLogGroups', cloudwatchRegion]) || {};

                            if (regionLogGroups.err || !regionLogGroups.data) {
                                continue;
                            }

                            var foundLogGroup = regionLogGroups.data.find(logGroup => logGroup.logGroupName === lambdaEdgeLogGroupName);
                            if (foundLogGroup) {
                                result = [0, 'Function has lambda@edge log group: ' + foundLogGroup.logGroupName + ' in region: ' + cloudwatchRegion];
                                break;
                            }
                        }

                        if (result[1] === '') {
                            result = [2, 'Function has no log group'];
                        }
                    }
                } else {
                    result = [3, 'Unable to obtain log groups for Lambda'];
                }

                helpers.addResult(results, result[0], result[1], region, arn);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};