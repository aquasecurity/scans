var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ALB Security Group',
    category: 'ELBv2',
    domain: 'Content Delivery',
    description: 'Ensures that Application Load Balancer has security group associated.',
    more_info: 'It is a security best practice to always have application load balancers associated with security groups to avoid any data loss or unauthorized access.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html',
    recommended_action: 'Modify Application Load Balancer and add security group.',
    apis: ['ELBv2:describeLoadBalancers'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        async.each(regions.elbv2, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();
            
            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for load balancers: ' +  helpers.addError(describeLoadBalancers),
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            for (let alb of describeLoadBalancers.data){

                if (!alb.LoadBalancerArn || (!alb.Type || alb.Type.toLowerCase() !== 'application')) {
                    continue;
                }

                if (alb.SecurityGroups && alb.SecurityGroups.length){
                    helpers.addResult(results, 0, 'Application Load Balancer has security group associated', region, alb.LoadBalancerArn);
                } else {
                    helpers.addResult(results, 2, 'Application Load Balancer does not have security group associated', region, alb.LoadBalancerArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};