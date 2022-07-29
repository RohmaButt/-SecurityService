using Afiniti.GRM.SecurityDTO;
using System.Collections.Generic;
using System.Linq;
using System.Configuration;
using System;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_JiraMobile
    {
        public CrowdUserObj AuthenticateUser_JiraMobile(string UserName, string Password)
        {
            CrowdUserObj crowdUserObj = AuthenticateUserFromCrowdForJiraMobile(UserName, Password);

            //CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
            //       ConfigurationManager.AppSettings["CrowdAppName"],
            //       ConfigurationManager.AppSettings["CrowdAppPass"]);

            //UserObj uObj =  crowdService.GetUserFromCrowd(UserName);
            //crowdUserObj.DisplayName = uObj.DisplayName;

            //UserObj uObjForAvatar = crowdService.GetUserAvatarFromCrowd(UserName);
            //crowdUserObj.AvatarURL = uObj.AvatarURL;

            return crowdUserObj;
        }
        public void SendApprovalRequestEmailFromJiraMobile(string UserName, string Message)
        {
            SendApprovalRequestEmail(UserName, Message);
        }

        public bool LogoutFromJiraMobile(string CrowdSSOToken)
        {
            return RemoveSSOTokenFromCrowd(CrowdSSOToken);
        }

        public CrowdUserObj GetValidUserToken_JiraMobile(string crowd_ssoToken, string userName)
        {
            //Utilities.LogException(new Exception("GetValidUserToken_JiraMobile With Params " + crowd_ssoToken + " USerName: " + userName), null);

            CrowdUserObj validToken = GetUserObjectFromCrowdToken(crowd_ssoToken);

            if (validToken.JSessionID == null)
            {
                validToken = AuthenticateUserFromCrowdByUserName(userName);
                //Utilities.LogException(new Exception("validToken Created: " + validToken.JSessionID + validToken.CrowdSSOToken), null);

            }
            else
            {
                validToken.CrowdSSOToken = crowd_ssoToken;
                validToken.AuthenticationCode = 1;

                //Utilities.LogException(new Exception("Token is already valid: " + validToken.JSessionID + validToken.CrowdSSOToken), null);
            }

            return validToken;
        }

        public AppConfiguration GetJiraAppConfig(string appName)
        {

            AppConfiguration configData = new AppConfiguration();
            try
            {
                //Utilities.LogException(new Exception("GetJiraAppConfig for " + appName), null);
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    var query = from apps in ctx.SecurityApps
                                join config in ctx.SecurityApps_Configuration
                                on apps.AppKey equals config.AppKey
                                where apps.AppName.ToLower() == appName.Trim().ToLower()
                                select config;
                    List<SecurityApps_Configuration> data = query.ToList();
                    if (data.Any())
                    {
                        configData.AppVersion = data.Where(x => x.ConfigKey == "CurrentAppVer")
                            .Select(y => y.ConfigValue)
                            .FirstOrDefault();
                        configData.DownloadUrl = data.Where(x => x.ConfigKey == "AppDownloadURL")
                            .Select(y => y.ConfigValue)
                            .FirstOrDefault();
                    }

                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, null);
            }

            return configData;
        }
    }
}