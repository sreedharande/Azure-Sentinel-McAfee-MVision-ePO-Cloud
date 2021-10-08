# Azure-Sentinel-McAfee-MVision-ePO-Cloud
Azure Sentinel custom Data connector to ingest cloud based McAfee MVISION ePO Events

## **Pre-requisites**

1. Sign up for an MVISION ePO account: https://mvision.mcafee.com  
2. McAfee sends a user activation email and a welcome email containing the MVISION ePO URL. Activate your account before logging on to MVISION ePO  
3. Log on to MVISION ePO and deploy Endpoint Security to client systems  
4. Configure McAfee Event Receiver to use Threat Events API  
5. Generate Client Id 
   - Login to the MVISION EPO console and open a new tab  
   - Go to https://auth.ui.mcafee.com/support.html to retrieve your client_id

## Configuration Steps to Deploy Function App
1. Click on Deploy to Azure (For both Commercial & Azure GOV)  
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsreedharande%2FAzure-Sentinel-McAfee-MVision-ePO-Cloud%2Fmain%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fsreedharande%2FAzure-Sentinel-McAfee-MVision-ePO-Cloud%2Fmain%2Fazuredeploy.json)

  
