var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Empty Groups',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensures all groups have at least one member.',
    more_info: 'While having empty groups does not present a direct security risk, it does broaden the management landscape which could potentially introduce risks in the future.',
    link: 'https://docs.oracle.com/cd/E10391_01/doc.910/e10360/usergroups.htm',
    recommended_action: 'Remove identity groups with no members.',
    apis: ['group:list', 'userGroupMembership:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var defaultRegion = '';

        if (cache.group.list &&
            Object.keys(cache.group.list).length &&
            Object.keys(cache.group.list).length > 0){
            defaultRegion = helpers.objectFirstKey(cache.group.list);
        } else {
            return callback(null, results, source);
        }

        var groups = helpers.addSource(cache, source,
            ['group', 'list', defaultRegion]);

        var userGroups = helpers.addSource(cache, source,
            ['userGroupMembership', 'list', defaultRegion]);

        if (!groups || !userGroups) return callback(null, results, source);

        if (groups.err || !groups.data || userGroups.err  || !userGroups.data) {
            helpers.addResult(results, 3,
                'Unable to query user groups: ' + helpers.addError(userGroups));
            return callback(null, results, source);
        }

        if (!groups.data.length || !userGroups.data.length) {
            helpers.addResult(results, 0, 'No groups found');
            return callback(null, results, source);
        }

        for (g in groups.data) {
            var group = groups.data[g];

            var users = userGroups.data.filter((u) => {
                if (u.groupId) return u.groupId === group.id;
            });

            if (users && users.length) {
                helpers.addResult(results, 0, `Group: ${group.name} contains ${users.length} user(s)`, defaultRegion, group.id);
            } else {
                helpers.addResult(results, 1, `Group: ${group.name} does not contain any users`, defaultRegion,group.id)
            }
        }

        callback(null, results, source);
    }
};