// A storage account and a SQL server, as an AI assistant might write it in
// Bicep.

param location string = resourceGroup().location
param sqlAdminPassword string = 'Summer2026!'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stdemo${uniqueString(resourceGroup().id)}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
  }
}

resource sql 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: 'sql-demo'
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: sqlAdminPassword
  }
}

resource firewall 'Microsoft.Sql/servers/firewallRules@2023-08-01-preview' = {
  parent: sql
  name: 'AllowAll'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}
