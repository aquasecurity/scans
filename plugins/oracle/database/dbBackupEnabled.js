var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Database Backup Enabled',
    category: 'Database',
    domain: 'Databases',
    description: 'Ensures that all databases have auto backup enabled',
    more_info: 'Enabling automatic backup on databases ensures that all sensitive data is protected from unwarranted deletion or loss of data.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Database/Tasks/backingupOS.htm',
    recommended_action: 'when creating a new database, under advanced settings enable Auto Backup.',
    apis: ['dbHome:list','database:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
		var regions = helpers.regions(settings.govcloud);

        async.each(regions.database, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var databases = helpers.addSource(cache, source,
                    ['database', 'list', region]);

                if (!databases) return rcb();

                if (databases.err || !databases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for databases: ' + helpers.addError(databases), region);
                    return rcb();
                }

                if (!databases.data.length) {
                    helpers.addResult(results, 0, 'No databases found', region);
                    return rcb();
                }

                databases.data.forEach(database  => {
                    if (database.dbBackupConfig &&
                        database.dbBackupConfig.autoBackupEnabled) {
                        helpers.addResult(results, 0, 'The database has auto backup enabled', region, database.id);
                    } else {
                        helpers.addResult(results, 2, 'The database has auto backup disabled', region, database.id);
                    }
                });
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};