using System;
using System.Collections.Generic;
using System.Linq;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_GenieMobile
    {
        public CrowdUserObj AuthenticateUser_GenieMobile(string UserName, string Password)
        {
            return AuthenticateUserFromCrowdForGenieMobile(UserName, Password);
        }

        public CrowdUserObj GetUserRemoteKeyByEmail(string email)
        {
            return GetUserRemoteKeyByEmailOnly(email);
        }

        public void SendApprovalRequestEmailFromGenieMobile(string UserName, string Message)
        {
            SendApprovalRequestEmail(UserName, Message);
        }

        public bool LogoutFromGenieMobile(string CrowdSSOToken)
        {
            return RemoveSSOTokenFromCrowd(CrowdSSOToken);
        }

        public AppConfiguration GetGenieAppConfig_IOS()
        {

            AppConfiguration configData = new AppConfiguration();
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    var query = from apps in ctx.SecurityApps
                                join config in ctx.SecurityApps_Configuration
                                on apps.AppKey equals config.AppKey
                                where apps.AppName.ToLower() == "geniemobileios"
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

                throw;
            }

            return configData;
        }
    }
}