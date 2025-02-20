# CloudSploit For Microsoft Azure

## Cloud Provider Configuration
1. Create an App Registraion
    1. Log into your Azure Portal and navigate to the Azure Active Directory service.
    1. Select App registrations and then click on New registration.
    1. Enter "CloudSploit" and/or a descriptive name in the Name field, take note of it, it will be used again in step 3.
    1. Leave the "Supported account types" default: "Accounts in this organizational directory only (YOURDIRECTORYNAME)".
    1. Click on Register.
    1. Copy the Application ID and Paste it below.
    1. Copy the Directory ID and Paste it below.
1. Create an App secret
    1. Click on Certificates & secrets.
    1. Under Client secrets, click on New client secret.
    1. Enter a Description (i.e. Cloudsploit-2019) and select Expires "365 days (12 months)".
    1. Click on Add.
    1. The Client secret value appears only once, make sure you store it safely.
1. Allow the App access to a Subscription
    1. Navigate to Subscriptions.
    1. Click on the relevant Subscription ID, copy and paste the ID below.
    1. Click on "Access Control (IAM)".
    1. Go to the Role assignments tab.
    1. Create a custom CloudSploit role
        1. Click on "Add", then "Add custom role".
        1. Enter "CloudSploit" for the Custom role name
        1. Select the JSON tab, then Edit
        1. Paste in the below JSON's "actions"
            1. This is a combination of "Security Reader", "Log Analytics Reader", and "Storage Account Key Operator Service Role".
        1. Save the custom role
    1. Assign the custom role to the App
        1. Go to the Role assignments tab.
        1. Click on "Add", then "Add role assignment".
        1. In the "Role" drop-down, select the custom role we created above (e.g. "CloudSploit").
        1. Leave the "Assign access to" default value.
        1. In the "Select" drop-down, type the name of the app registration (e.g. "CloudSploit") you created and select it.
        1. Click "Save".

```json
{
    "properties": {
        "roleName": "CloudSploit",
        "description": "",
        "assignableScopes": [
            "/subscriptions/<YOUR SUBSCRIPTION>"
        ],
        "permissions": [
            {
                "actions": [
                    "Microsoft.Authorization/*/read",
                    "Microsoft.Insights/alertRules/read",
                    "Microsoft.operationalInsights/workspaces/*/read",
                    "Microsoft.Resources/deployments/*/read",
                    "Microsoft.Resources/subscriptions/resourceGroups/read",
                    "Microsoft.Security/*/read",
                    "Microsoft.IoTSecurity/*/read",
                    "Microsoft.Support/*/read",
                    "Microsoft.Security/iotDefenderSettings/packageDownloads/action",
                    "Microsoft.Security/iotDefenderSettings/downloadManagerActivation/action",
                    "Microsoft.Security/iotSensors/downloadResetPassword/action",
                    "Microsoft.IoTSecurity/defenderSettings/packageDownloads/action",
                    "Microsoft.IoTSecurity/defenderSettings/downloadManagerActivation/action",
                    "Microsoft.Management/managementGroups/read",
                    "Microsoft.Network/networkWatchers/read",
                    "Microsoft.Storage/storageAccounts/listkeys/action",
                    "Microsoft.Storage/storageAccounts/regeneratekey/action"
				],
                "notActions": [],
                "dataActions": [],
                "notDataActions": []
            }
        ]
    }
}
```

