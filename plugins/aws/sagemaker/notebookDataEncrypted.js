var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Notebook Data Encrypted',
    category: 'AI & ML',
    owasp: ['LLM07', 'LLM02', 'LLM10'],
    domain: 'Compute',
    severity: 'High',
    description: 'Ensure Notebook data is encrypted',
    more_info: 'An optional encryption key can be supplied during Notebook Instance creation.',
    recommended_action: 'An existing KMS key should be supplied during Notebook Instance creation.',
    link: 'https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateNotebookInstance.html#API_CreateNotebookInstance_RequestSyntax',
    apis: ['SageMaker:listNotebookInstances'],
    compliance: {
        hipaa: 'All data in HIPAA environments must be encrypted, including ' +
                'data at rest. SageMaker encryption ensures Notebook data is ' +
                'encrypted at rest.'
    },
    realtime_triggers: ['sagemaker:CreateNotebookInstance', 'sagemaker:DeleteNotebookInstance'],

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

                if (!instance.KmsKeyId){
                    helpers.addResult(results, 2,
                        'KMS key not found for Notebook Instance', region, instanceArn);
                } else {
                    helpers.addResult(results, 0,
                        'KMS key found for Notebook Instance', region, instanceArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
