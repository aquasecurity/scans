var expect = require('chai').expect;
var storage = require('./ddosStandardProtectionEnabled');

const virtualNetworks = [
    {
        name: 'test-vnet',
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/deleteASAP-vnet',
        type: 'Microsoft.Network/virtualNetworks',
        location: 'eastus',
        provisioningState: 'Succeeded',
        virtualNetworkPeerings: [],
        enableDdosProtection: true
    },
    {
        name: 'test-vnet',
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/deleteASAP-vnet',
        type: 'Microsoft.Network/virtualNetworks',
        location: 'eastus',
        provisioningState: 'Succeeded',
        virtualNetworkPeerings: [],
        enableDdosProtection: false
    }
];

const createCache = (virtualNetworks) => {
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {
                    data: virtualNetworks
                }
            }
        }
    };
};

describe('ddosStandardProtectionEnabled', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const cache = createCache([]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if DDoS standard protection is not enabled for postgresql server', function(done) {
            const cache = createCache([virtualNetworks[1]]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('DDoS Standard Protection is not enabled for Microsoft Azure Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if storage auto growth is enabled for postgresql server', function(done) {
            const cache = createCache([virtualNetworks[0]]);
            storage.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('DDoS Standard Protection is enabled for Microsoft Azure Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 