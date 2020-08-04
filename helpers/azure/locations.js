// Source: https://azure.microsoft.com/en-us/global-infrastructure/services/

var locations = [
    'eastasia',
    'southeastasia',
    'centralus',
    'eastus',
    'eastus2',
    'westus',
    'northcentralus',
    'southcentralus',
    'northeurope',
    'westeurope',
    'germanycentral',
    'germanynortheast',
    'germanywestcentral',
    'germanynorth',
    'switzerlandnorth',
    'switzerlandwest',
    'norwaywest',
    'norwayeast',
    'japanwest',
    'japaneast',
    'brazilsouth',
    'australiaeast',
    'australiasoutheast',
    'southindia',
    'centralindia',
    'westindia',
    'canadacentral',
    'canadaeast',
    'uksouth',
    'ukwest',
    'westcentralus',
    'westus2',
    'koreacentral',
    'koreasouth',
    'francecentral',
    'francesouth',
    'australiacentral',
    'australiacentral2',
    'southafricanorth',
    'southafricawest',
    'uaenorth',
    'uaecentral'
];

module.exports = {
    all: locations,
    resources: locations,
    storageAccounts: locations,
    virtualMachines: locations,
    disks: locations,
    activityLogAlerts: ['global'],
    vaults: locations,
    policyAssignments: locations.concat(['global']),
    webApps: locations,
    networkSecurityGroups: locations,
    servers: locations,
    logProfiles: ['global'],
    profiles: ['global'],
    managementLocks: ['global'],
    networkWatchers: locations,
    managedClusters: locations,
    virtualMachineScaleSets: locations,
    autoProvisioningSettings: ['global'],
    securityContacts: ['global'],
    usages: ['global'],
    subscriptions: ['global'],
    loadBalancers: locations,
    availabilitySets: locations,
    virtualNetworks: locations,
    users: ['global'],
    registries: locations,
    pricings: ['global'],
    roleDefinitions: ['global'],
    autoscaleSettings: locations,
    resourceGroups: locations,
    policyDefinitions: locations,
    diagnosticSettingsOperations: ['global']
};
