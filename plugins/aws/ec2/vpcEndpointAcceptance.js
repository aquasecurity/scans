var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC PrivateLink Endpoint Acceptance Required',
    category: 'EC2',
    description: 'Ensures VPC PrivateLink endpoints require acceptance',
    more_info: 'VPC PrivateLink endpoints should be configured to require acceptance so that access to the endpoint is controlled on a case-by-case basis.',
    recommended_action: 'Update the VPC PrivateLink endpoint to require acceptance',
    link: 'https://docs.aws.amazon.com/vpc/latest/userguide/accept-reject-endpoint-requests.html',
    apis: ['EC2:describeVpcEndpointServices'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeVpcEndpointServices = helpers.addSource(cache, source,
                ['ec2', 'describeVpcEndpointServices', region]);

            if (!describeVpcEndpointServices) return rcb();

            if (describeVpcEndpointServices.err || !describeVpcEndpointServices.data) {
                helpers.addResult(results, 3,
                    'Unable to query for vpc endpoint services: ' + helpers.addError(describeVpcEndpointServices), region);
                return rcb();
            }

            if (!describeVpcEndpointServices.data.length) {
                helpers.addResult(results, 0, 'No vpc endpoint services present', region);
                return rcb();
            }

            for (var s in describeVpcEndpointServices.data) {
                var service = describeVpcEndpointServices.data[s];
                var resource = service.ServiceId;
                if (service.AcceptanceRequired === false) {
                    helpers.addResult(results, 2,
                        'Vpc endpoint service ' + (service.ServiceId) + ' does not require acceptance',
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Vpc endpoint service ' + (service.ServiceId) + ' requires acceptance',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};