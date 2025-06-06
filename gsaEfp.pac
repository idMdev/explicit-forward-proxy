function FindProxyForURL(url, host) {
  // Update the TenantId with your own tenant (must be enrolled in the GSA EFP preview)
  var tenantId = "beee99f9-ff92-4b15-bddd-652c8204f79f";
  var efpEndpoint = "efp.ztna.azureedge-test.net";
  var efpUrl = "HTTPS " + tenantId + "." + efpEndpoint;

  //----------------------PROXY MODE CONFIGURATION----------------------//
  // Set to true for ALL-PROXY mode: All traffic goes through EFP except exclusions
  // Set to false for SOME-PROXY mode: Only specified domains go through EFP
  var ALL_PROXY_MODE = true;
  //----------------------PROXY MODE CONFIGURATION----------------------//


  //----------------------Start Admin-Defined Proxy Domains----------------------//
  // Domains that MUST go through EFP (for SOME_PROXY_MODE)
  //var customInclusions = [
  //  "www.facebook.com",
  //  "*.facebook.com",
  //  "www.yahoo.com",
  //  "*.yahoo.com",
  //  "www.openai.com",
  //  "*.openai.com"
  //];
  //----------------------End Admin-Defined Proxy Domains----------------------//

  //----------------------Start Admin-Defined Exclusions----------------------//
  // Add any additional domains that should bypass EFP
  var customExclusions = [
    // "*.internal.contoso.com",
    // "vpn.contoso.com"
  ];
  //----------------------End Admin-Defined Exclusions----------------------//

  //----------------------Start Authentication FQDNs bypassed by EFP----------------------//
  //CRITICAL: DO NOT MODIFY Entra ID Authentication URLs. These must be bypassed for EFP to work correctly.
  var requiredAuth = [
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.windows.net",
    "login.microsoftonline-p.com",
    "loginex.microsoftonline.com",
    "login-us.microsoftonline.com",
    "login.live.com",
    "aadcdn.msftauth.net",
    "msftauth.net",
    "aadcdn.msauth.net"
  ];

  //IMPORTANT: If you are using a federated identity provider with Entra ID, you may need to add additional domains here.
  var requiredAuthFederated = [
    // Add your federated identity provider domains here
    // "adfs.yourdomain.com",
    // "sso.yourdomain.com",
    // "idp.yourdomain.com"
  ];
  //----------------------End Authentication FQDNs bypassed by EFP----------------------//

  //----------------------Start M365 FQDNs bypassed by EFP----------------------//
  //GSA Explicit Forward Proxy requires TLS inspection.
  // Microsoft 365 network connectivity principles guide against TLS inspection. https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-network-connectivity-principles
  var m365Portal = [
    "portal.office.com",
    "www.office.com",
    "portal.office365.com",
    "home.office.com",
    "admin.microsoft.com",
    "portal.azure.com"
  ];

  var m365Exchange = [
    "outlook.office.com",
    "outlook.office365.com",
    "*.outlook.office.com",
    "*.outlook.office365.com",
    "outlook.live.com",
    "*.protection.outlook.com",
    "*.mail.protection.outlook.com"
  ];

  var m365SharePoint = [
    "*.sharepoint.com",
    "*.sharepoint-df.com",
    "*-my.sharepoint.com",
    "*-myfiles.sharepoint.com",
    "*.sharepointonline.com"
  ];

  var m365Teams = [
    "*.teams.microsoft.com",
    "teams.microsoft.com",
    "*.teams.skype.com",
    "*.broadcast.skype.com",
    "*.sfbassets.com",
    "skypemaprdsitus.trafficmanager.net",
    "*.keydelivery.mediaservices.windows.net",
    "*.streaming.mediaservices.windows.net"
  ];
  //----------------------End M365 FQDNs bypassed by EFP----------------------//

  // Combine all mandatory exclusions (these ALWAYS bypass EFP regardless of mode)
  var mandatoryExclusions = []
    .concat(requiredAuth)
    .concat(requiredAuthFederated)
    .concat(m365Portal)
    .concat(m365Exchange)
    .concat(m365SharePoint)
    .concat(m365Teams);

  // Check mandatory exclusions first (highest priority - always bypass EFP)
  for (var i = 0; i < mandatoryExclusions.length; i++) {
    if (mandatoryExclusions[i].indexOf("*") !== -1) {
      if (shExpMatch(host, mandatoryExclusions[i])) {
        return "DIRECT";
      }
    } else {
      if (dnsDomainIs(host, mandatoryExclusions[i])) {
        return "DIRECT";
      }
    }
  }

  // Check branch auth (always goes through EFP)
  if (dnsDomainIs(host, "ia.branch-auth.ztna.azureedge-test.net")) {
    return efpUrl;
  }

  // Mode-specific logic
  if (ALL_PROXY_MODE) {
    // Everything goes through EFP except exclusions
    // Check admin-defined exclusions
    for (var j = 0; j < customExclusions.length; j++) {
      if (customExclusions[j].indexOf("*") !== -1) {
        if (shExpMatch(host, customExclusions[j])) {
          return "DIRECT";
        }
      } else {
        if (dnsDomainIs(host, customExclusions[j])) {
          return "DIRECT";
        }
      }
    }
    // Defaul - go through proxy
    return efpUrl;
  } else {
    // Only specified domains go through EFP
    // Check if host matches admin-defined proxy domains
    for (var k = 0; k < customInclusions.length; k++) {
      if (adminProxyDomains[k].indexOf("*") !== -1) {
        if (shExpMatch(host, customInclusions[k])) {
          return efpUrl;
        }
      } else {
        if (dnsDomainIs(host, customInclusions[k])) {
          return efpUrl;
        }
      }
    }
    // Default - go direct
    return "DIRECT";
  }
}