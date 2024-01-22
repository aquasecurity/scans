const {
    CloudWatch
} = require('@aws-sdk/client-cloudwatch');
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudwatch = new CloudWatch(AWSConfig);

    async.eachLimit(collection.ec2.describeInstances[AWSConfig.region].data, 10, function(reservation, cb) {
        reservation.Instances.forEach(instance => {
            collection.cloudwatch.getEc2MetricStatistics[AWSConfig.region][instance.InstanceId] = {};
            var endTime = new Date();
            var startTime = new Date();
            startTime.setDate(startTime.getDate() - 1);
            var params = {
                'MetricName': 'CPUUtilization',
                'Namespace': 'AWS/EC2',
                'StartTime': startTime,
                'EndTime': endTime,
                'Period': 3600,
                'Statistics': ['Average'],
                'Dimensions': [
                    {
                        Name: 'InstanceId',
                        Value: instance.InstanceId
                    }
                ]
            };

            helpers.makeCustomCollectorCall(cloudwatch, 'getMetricStatistics', params,retries, null, null, null, function(err, data) {
                if (err) collection.cloudwatch.getEc2MetricStatistics[AWSConfig.region][instance.InstanceId].err = err;
                if (data) collection.cloudwatch.getEc2MetricStatistics[AWSConfig.region][instance.InstanceId].data = data;
            });
        });
        cb();
    }, function() {
        callback();
    });
};
