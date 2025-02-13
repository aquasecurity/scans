var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Private Endpoint',
    category: 'EKS',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures the private endpoint setting is enabled for EKS clusters',
    more_info: 'EKS private endpoints can be used to route all traffic between the Kubernetes worker and control plane nodes over a private VPC endpoint rather than across the public internet.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html',
    recommended_action: 'Disable the public endpoint setting for all EKS clusters.',
    apis: ['EKS:listClusters', 'EKS:describeCluster', 'STS:getCallerIdentity'],
    realtime_triggers: ['eks:CreateCluster', 'eks:updateClusterConfig', 'eks:DeleteCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.eks, function(region, rcb) {
            var listClusters = helpers.addSource(cache, source,
                ['eks', 'listClusters', region]);

            if (!listClusters) return rcb();

            if (listClusters.err || !listClusters.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for EKS clusters: ' + helpers.addError(listClusters), region);
                return rcb();
            }

            if (listClusters.data.length === 0){
                helpers.addResult(results, 0, 'No EKS clusters present', region);
                return rcb();
            }

            for (var c in listClusters.data) {
                var clusterName = listClusters.data[c];
                var describeCluster = helpers.addSource(cache, source,
                    ['eks', 'describeCluster', region, clusterName]);

                var arn = 'arn:' + awsOrGov + ':eks:' + region + ':' + accountId + ':cluster/' + clusterName;

                if (!describeCluster || describeCluster.err || !describeCluster.data) {
                    helpers.addResult(
                        results, 3,
                        'Unable to describe EKS cluster: ' + helpers.addError(describeCluster),
                        region, arn);
                    continue;
                }

                if (describeCluster.data.cluster &&
                    describeCluster.data.cluster.resourcesVpcConfig &&
                    describeCluster.data.cluster.resourcesVpcConfig.endpointPublicAccess) {
                    helpers.addResult(results, 2, 'EKS cluster has public endpoint enabled', region, arn);
                } else {
                    helpers.addResult(results, 0, 'EKS cluster has public endpoint disabled', region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
