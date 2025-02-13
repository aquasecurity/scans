var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Amazon Comprehend Output Result Encryption',
    category: 'AI & ML',
    owasp: ['LLM07', 'LLM02'],
    domain: 'Compute',
    severity: 'High',
    description: 'Ensures the Comprehend service is using encryption for all result output.',
    more_info: 'Comprehend supports using KMS keys to result output, which should be enabled.',
    link: 'https://docs.aws.amazon.com/comprehend/latest/dg/kms-in-comprehend.html',
    recommended_action: 'Enable output result encryption for the Comprehend job',
    apis: ['Comprehend:listEntitiesDetectionJobs', 'Comprehend:listDominantLanguageDetectionJobs', 'Comprehend:listTopicsDetectionJobs',
        'Comprehend:listDocumentClassificationJobs', 'Comprehend:listKeyPhrasesDetectionJobs', 'Comprehend:listSentimentDetectionJobs'],
    realtime_triggers: ['comprehend:StartEntitiesDetectionJob','comprehend:StartTopicsDetectionJob','comprehend:StartSentimentDetectionJob','comprehend:StartKeyPhrasesDetectionJob','comprehend:StartDominantLanguageDetectionJob'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var regions = helpers.regions(settings);

        async.each(regions.comprehend, function(region, rcb) {
            async.parallel([
                function(lcb){
                    var listEntitiesDetectionJobs = helpers.addSource(cache, source,
                        ['comprehend', 'listEntitiesDetectionJobs', region]);
                        
                    if (!listEntitiesDetectionJobs) return lcb();

                    if (listEntitiesDetectionJobs.err || !listEntitiesDetectionJobs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for entities detections jobs', region);
                        return lcb();
                    }

                    if (!listEntitiesDetectionJobs.data.length) {
                        helpers.addResult(results, 0,
                            'No entities detection jobs found', region);
                        return lcb();
                    }

                    loopJobsForResults(listEntitiesDetectionJobs, results, region);

                    lcb();
                },
                function(lcb){
                    var listDocumentClassificationJobs = helpers.addSource(cache, source,
                        ['comprehend', 'listDocumentClassificationJobs', region]);

                    if (!listDocumentClassificationJobs) return lcb();
                    
                    if (listDocumentClassificationJobs.err || !listDocumentClassificationJobs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for document classification jobs', region);
                        return lcb();
                    }

                    if (!listDocumentClassificationJobs.data.length) {
                        helpers.addResult(results, 0,
                            'No document classification jobs found', region);
                        return lcb();
                    }
                    
                    loopJobsForResults(listDocumentClassificationJobs, results, region);

                    lcb();
                },
                function(lcb){
                    var listDominantLanguageDetectionJobs = helpers.addSource(cache, source,
                        ['comprehend', 'listDominantLanguageDetectionJobs', region]);
                    
                    if (!listDominantLanguageDetectionJobs) return lcb();

                    if (listDominantLanguageDetectionJobs.err || !listDominantLanguageDetectionJobs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for dominant language detection jobs', region);
                        return lcb();
                    }

                    if (!listDominantLanguageDetectionJobs.data.length) {
                        helpers.addResult(results, 0,
                            'No dominant language detection jobs found', region);
                        return lcb();
                    }

                    loopJobsForResults(listDominantLanguageDetectionJobs, results, region);

                    lcb();
                },
                function(lcb){                    
                    var listTopicsDetectionJobs = helpers.addSource(cache, source,
                        ['comprehend', 'listTopicsDetectionJobs', region]);
                    
                    if (!listTopicsDetectionJobs) return lcb();

                    if (listTopicsDetectionJobs.err || !listTopicsDetectionJobs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for topics detection jobs', region);
                        return lcb();
                    }

                    if (!listTopicsDetectionJobs.data.length) {
                        helpers.addResult(results, 0,
                            'No topics detection jobs found', region);
                        return lcb();
                    }

                    loopJobsForResults(listTopicsDetectionJobs, results, region);

                    lcb();
                },
                function(lcb){       
                    var listKeyPhrasesDetectionJobs = helpers.addSource(cache, source,
                        ['comprehend', 'listKeyPhrasesDetectionJobs', region]);
                    
                    if (!listKeyPhrasesDetectionJobs) return lcb();

                    if (listKeyPhrasesDetectionJobs.err || !listKeyPhrasesDetectionJobs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for key phrases detection jobs', region);
                        return lcb();
                    }

                    if (!listKeyPhrasesDetectionJobs.data.length) {
                        helpers.addResult(results, 0,
                            'No key phrases detection jobs found', region);
                        return lcb();
                    }

                    loopJobsForResults(listKeyPhrasesDetectionJobs, results, region);

                    lcb();
                },
                function(lcb){                    
                    var listSentimentDetectionJobs = helpers.addSource(cache, source,
                        ['comprehend', 'listSentimentDetectionJobs', region]);
                    
                    if (!listSentimentDetectionJobs) return lcb();

                    if (listSentimentDetectionJobs.err || !listSentimentDetectionJobs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for sentiment detection jobs', region);
                        return lcb();
                    }

                    if (!listSentimentDetectionJobs.data.length) {
                        helpers.addResult(results, 0,
                            'No sentiment detection jobs found', region);
                        return lcb();
                    }

                    loopJobsForResults(listSentimentDetectionJobs, results, region);

                    lcb();
                },
            ], function(){
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};

function loopJobsForResults(jobs, results, region) {
    for (var j in jobs.data) {
        var job = jobs.data[j];
        var resource = job.JobId;

        if (!job.OutputDataConfig || !job.OutputDataConfig.KmsKeyId) {
            helpers.addResult(results, 2,
                'Output result encryption is not enabled for: ' + job.JobName + ' job',
                region, resource);
        } else {
            helpers.addResult(results, 0,
                'Output result encryption is enabled for: ' + job.JobName + ' job',
                region, resource);
        }
    }
}