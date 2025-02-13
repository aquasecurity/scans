var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Notebook instance in VPC',
    category: 'AI & ML',
    owasp: ['LLM07'],
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that Amazon SageMaker Notebook instances are launched within a VPC.',
    more_info: 'Launching instances can bring multiple advantages such as better networking infrastructure, much more flexible control over access security. Also it makes it possible to access VPC-only resources such as EFS file systems.',
    recommended_action: 'Migrate Notebook instances to exist within a VPC',
    link: 'https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateNotebookInstance.html#API_CreateNotebookInstance_RequestSyntax',
    apis: ['SageMaker:listNotebookInstances', 'SageMaker:describeNotebookInstance'],
    compliance: {
        hipaa: 'AWS VPC is the recommended location for processing of HIPAA-related ' +
            'data. All instances storing or processing HIPAA data should be ' +
            'launched in a VPC to avoid exposure to the public network.',
        pci: 'VPCs provide a firewall for compute resources that meets the network ' +
            'segmentation criteria for PCI. Ensure all instances are launched ' +
            'within a VPC to comply with isolation requirements.'
    },
    realtime_triggers: ['sagemaker:CreateNotebookInstance','sagemaker:DeleteNotebookInstance'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.sagemaker, function(region, rcb){
            var listNotebookInstances = helpers.addSource(cache, source,
                ['sagemaker', 'listNotebookInstances', region]);

            if (!listNotebookInstances) return rcb();

            if (listNotebookInstances.err) {
                helpers.addResult(results, 3,
                    'Unable to query for Notebook Instances: ' +
                    helpers.addError(listNotebookInstances), region);
                return rcb();
            }

            if (!listNotebookInstances.data || !listNotebookInstances.data.length) {
                helpers.addResult(
                    results, 0, 'No Notebook Instances Found', region);
                return rcb();
            }

            for (var i in listNotebookInstances.data) {
                var instance = listNotebookInstances.data[i];
                var instanceArn = instance.NotebookInstanceArn;

                // A network interface is assigned when the notebook is VPC-based.
                // Similarly, the instance must be assigned to a subnet if it is VPC-based.
                var describeInstance = helpers.addSource(cache, source,
                    ['sagemaker', 'describeNotebookInstance', region, instance.NotebookInstanceName]);
                
                if (!describeInstance) return;
                
                else if (describeInstance.err || !describeInstance.data) {
                    helpers.addResult(
                        results, 3, 'Unable to query for Notebook Instance: ' +
                        helpers.addError(describeInstance), region);
                    return;
                } else {
                    if (!describeInstance.data.NetworkInterfaceId) {
                        helpers.addResult(results, 2,
                            'SageMaker Notebook instance not in VPC', region, instanceArn);
                    } else {
                        helpers.addResult(results, 0,
                            'SageMaker Notebook instance in VPC', region, instanceArn);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
