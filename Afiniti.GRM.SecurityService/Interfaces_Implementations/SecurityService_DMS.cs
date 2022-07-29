using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Afiniti.GRM.SecurityDTO;
using System.Configuration;
using System.Linq.Expressions;
using System.Net;
using System.IO;
using Newtonsoft.Json;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_DMS
    {
        public CrowdUserObjMobile AuthenticateUser_DMSMAC(string UserName, string Password,Guid AppKey)
        {
            var exc = new Exception("in: AuthenticateUserFromCrowdForJiraMobile");
            //Utilities.LogException(exc, "");

            Afiniti.GRM.SecurityDTO.CrowdUserObjMobile crowdUserObj = new CrowdUserObjMobile()
            {
                AuthenticationCode = 2,
                ApprovalStatus = 1
            };
            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                    ConfigurationManager.AppSettings["CrowdAppName"],
                    ConfigurationManager.AppSettings["CrowdAppPass"]);

                var res = crowdService.CreateCrowdToken_internal(UserName, Password);
                if (res)
                {
                    crowdUserObj.AuthenticationCode = 1;
                    exc = new Exception("Authenticated from crowd");
                    //Utilities.LogException(exc, "");
                    exc = new Exception("Authenticated from crowd");
                    //Utilities.LogException(exc, "");

                    using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                    {
                        IQueryable<User> users = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                                                                      && x.IsActive == true);
                        Expression<Func<User, bool>> approvalCriteria = Utilities.CreateApprovalCriteria(GetApprovalPropertyNameByEndPoint());
                        exc = new Exception("Approval Criteria: " + approvalCriteria);
                        users = users.Where(approvalCriteria);
                        var user = users.FirstOrDefault();
                        if (user != null)
                        {
                            crowdUserObj.RemoteKey = user.UserRemoteKey.ToString();
                            crowdUserObj.UserKey = user.UserKey.ToString();
                            crowdUserObj.ApprovalStatus = user.DMSMACApproval;
                            crowdUserObj.UserName = user.UserName;
                            crowdUserObj.Email = user.Email;
                            crowdUserObj.CrowdSSOToken = crowdService.CROWD_TOKEN;
                            crowdUserObj.JSessionID = crowdService.CROWD_JSESSIONID;
                            crowdUserObj.AuthenticationMetaData = EncryptionClass.Encrypt_Decrypt(ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" + crowdService.CROWD_JSESSIONID + ";" + ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" + crowdService.CROWD_TOKEN, true);
                            crowdUserObj.AppConfiguration = GetAppConfig_DMSMAC(AppKey);

                            var fullUserObj = crowdService.GetUserFromCrowd(user.UserName);
                            //var jiraUserObj = GetJiraUserObj(user.UserName);
                            if (fullUserObj != null && !String.IsNullOrEmpty(fullUserObj.DisplayName))
                            {
                                crowdUserObj.DisplayName = fullUserObj.DisplayName;
                                //crowdUserObj.SpaceKey = jiraUserObj.key;
                            }
                            else
                            {
                                Utilities.LogException(new Exception("Unable to find Space Key for Username:" + user.UserName), "");
                            }

                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }
            exc = new Exception("Could not Authenticate from crowd");
            //Utilities.LogException(exc, "");
            return crowdUserObj;
        }

        public AppConfiguration GetAppConfig_DMSMAC(Guid appKey)
        {
            AppConfiguration configData = new AppConfiguration();
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    var query = from apps in ctx.SecurityApps
                                join config in ctx.SecurityApps_Configuration
                                on apps.AppKey equals config.AppKey
                                where apps.AppKey == appKey
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

        public CrowdUserObj GetValidUserToken_DMSMAC(string crowd_ssoToken, string userName)
        {
           return GetValidUserToken_JiraMobile(crowd_ssoToken, userName);
        }

        public bool Logout_DMSMAC(string CrowdSSOToken)
        {
            return RemoveSSOTokenFromCrowd(CrowdSSOToken);
        }

        public bool SendApprovalRequestEmail_DMSMAC(string UserName, string Message)
        {
            bool blnSent = false;
            try
            {
                SendApprovalRequestEmail_DmsMac(UserName, Message);
                blnSent = true;
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex,"");
                blnSent = false;
            }
            return blnSent;
        }

        //private ConfluenceUserObj GetJiraUserObj(string UserName)
        //{
        //    ConfluenceUserObj obj = new ConfluenceUserObj();
        //    try
        //    {
        //        var request = (HttpWebRequest)WebRequest.Create("https://support.afiniti.com/rest/api/2/user?username=" + UserName);
        //        request.ContentType = "application/json";
        //        request.Accept = "application/json";
        //        request.Method = "GET";
        //        var result = (HttpWebResponse)request.GetResponse();
        //        if (result.StatusCode == HttpStatusCode.OK)
        //        {
        //            using (var reader = new StreamReader(result.GetResponseStream()))
        //            {
        //                string strRes = reader.ReadToEnd();
        //                var json = JsonConvert.DeserializeObject<ConfluenceUserObj>(strRes);
        //                obj = json;
        //            }
        //        }
        //        else
        //        {
        //            obj = null;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Utilities.LogException(ex, "");
        //    }
        //    return obj;
        //}
    }
}