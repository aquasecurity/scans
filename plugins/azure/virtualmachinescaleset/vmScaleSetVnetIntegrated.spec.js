var expect = require('chai').expect;
var vmScaleSetVnetIntegrated = require('./vmScaleSetVnetIntegrated');

const vmScaleSet = [
    { "name": 'test',
      "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachineScaleSets/test",
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "location": "centralus",
      "tags": {
        "key" : "value"
      },
      "virtualMachineProfile": {
      "networkProfile": {
        "networkInterfaceConfigurations": [
          {
            "name": "pool12345",
            "properties": {
              "primary": true,
              "enableIPForwarding": true,
              "ipConfigurations": [
                {
                  "name": "ipconfig1",
                  "properties": {
                    "primary": true,
                    "subnet": {
                      "id": "/subscriptions/123456789/resourceGroups/MC_new-eastus-group_new-eastus-cluster_westus2/providers/Microsoft.Network/virtualNetworks/aks-vnet1234567890/subnets/aks-subnet",
                    },
                    "privateIPAddressVersion": "IPv4"
                  },
                },
              ],
            },
          },
        ],
      },
    },
    },
    { "name": 'test',
      "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/virtualMachineScaleSets/test",
      "type": "Microsoft.Compute/virtualMachineScaleSets",
      "location": "centralus",
      "virtualMachineProfile": {
      "networkProfile": {
        "networkInterfaceConfigurations": [
          {
            "name": "pool12345",
            "properties": {
              "primary": true,
              "enableIPForwarding": true,
              "ipConfigurations": [
              ],
            },
          },
        ],
      },
    },
},
];

const createCache = (vmScaleSet) => {
    return {
        vmScaleSet: {
            listAll: {
                'eastus': {
                    data: vmScaleSet
                }
            }
        }
    };
};

describe('vmScaleSetVnetIntegrated', function() {
    describe('run', function() {
        it('should give passing result if no scale set found', function(done) {
            const cache = createCache([]);
            vmScaleSetVnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing VM scale sets found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for scale set', function(done) {
            const cache = createCache();
            vmScaleSetVnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for VM scale sets');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if scale set has VNet integrated', function(done) {
            const cache = createCache([vmScaleSet[0]]);
            vmScaleSetVnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VM scale set has VNet Integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VM scale set does not have VNet integrated', function(done) {
            const cache = createCache([vmScaleSet[1]]);
            vmScaleSetVnetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VM scale set does not have VNet Integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});