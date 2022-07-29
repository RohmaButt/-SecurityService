using Afiniti.GRM.SecurityDTO;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_Insights
    {
        //[OperationContract(Name = "AuthenticateUser")]
        public AuthResponseModel AuthenticateUser_Insights(AuthRequestModel model)
        {
            AuthResponseModel res = null;
            Utilities.WriteTrace("Entering AuthenticateUser_Insights");
            try
            {

                if (model != null && !String.IsNullOrEmpty(model.UserName) && !String.IsNullOrEmpty(model.Password))
                {
                    LogRequest("AuthenticateUser", model.UserName, "insights");
                    res = new AuthResponseModel();
                    var crowdUser = AuthenticateUserFromCrowd(model.UserName, model.Password);
                    if (crowdUser != null && crowdUser.AuthenticationCode == 1 && !String.IsNullOrEmpty(crowdUser.CrowdSSOToken))
                    {
                        res.IsAuthenticated = true;
                        res.Message = "User Authenticated Successfully";
                        res.CrowdSSOToken = crowdUser.CrowdSSOToken;
                        res.JSessionID = crowdUser.JSessionID;
                        res.HttpStatusCode = System.Net.HttpStatusCode.OK;
                        CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                        ConfigurationManager.AppSettings["CrowdAppName"],
                        ConfigurationManager.AppSettings["CrowdAppPass"]);


                        var fullUserObj = crowdService.GetUserFromCrowd(model.UserName);
                        //var jiraUserObj = GetJiraUserObj(user.UserName);
                        if (fullUserObj != null && !String.IsNullOrEmpty(fullUserObj.DisplayName))
                        {
                            res.UserDisplayName = fullUserObj.DisplayName;
                            res.UserAvatarUrl = fullUserObj.AvatarURL;
                            //crowdUserObj.SpaceKey = jiraUserObj.key;
                        }
                    }
                    else
                    {
                        res.IsAuthenticated = false;
                        res.Message = "Authentication failed. Please check your credentials and try again";
                        res.CrowdSSOToken = null;
                        res.JSessionID = null;
                        res.HttpStatusCode = System.Net.HttpStatusCode.Unauthorized;
                    }
                }
                else
                {
                    LogRequest("AuthenticateUser", "-NoAutenticatedUser-", "insights");
                    res = new AuthResponseModel();

                    res.IsAuthenticated = false;
                    res.HttpStatusCode = System.Net.HttpStatusCode.BadRequest;
                    res.Message = "Invalid Parameters";
                }

            }
            catch (Exception ex)
            {
                res = new AuthResponseModel();
                res.IsAuthenticated = false;
                res.HttpStatusCode = System.Net.HttpStatusCode.InternalServerError;
                res.Message = "Something went wrong! Please reach out to Connect Team for assistance";
                Utilities.LogException(ex, "");
            }
            Utilities.WriteTrace("Exit AuthenticateUser_Insights");
            return res;
        }

        public bool Logout_Insights(string CrowdSSOToken)
        {
            bool loggedOut = false;
            Utilities.WriteTrace("Entering Logout_Insights");
            LogRequest("Logout", "-NoAutenticatedUser-", "insights");
            try
            {

                if (CrowdSSOToken != null && !String.IsNullOrEmpty(CrowdSSOToken))
                {
                    loggedOut = RemoveSSOTokenFromCrowd(CrowdSSOToken);
                }
                else
                {
                    loggedOut = false;
                }
            }
            catch (Exception ex)
            {
                loggedOut = false;
                Utilities.LogException(ex, "");
            }
            Utilities.WriteTrace("Exit Logout_Insights");
            return loggedOut;
        }

        public bool IsUserAuthenticated(string CrowdSSOToken)
        {
            bool res = false;
            Utilities.WriteTrace("Entering IsUserAuthenticated");

            try
            {
                Utilities.WriteTrace("Before GetUserObjectFromCrowdToken");
                CrowdUserObj obj = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (obj != null)
                {
                    if (String.IsNullOrEmpty(obj.UserName))
                    {
                        res = false;
                        LogRequest("IsUserAuthenticated", "-NoAutenticatedUser-", "insights");
                    }
                    else
                    {
                        res = true;
                        LogRequest("IsUserAuthenticated", obj.UserName, "insights");
                    }
                }
                else
                {
                    res = false;
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                res = false;
            }
            Utilities.WriteTrace("Exit IsUserAuthenticated");
            return res;
        }

        private void LogRequest(string RequestUrl = "", string RequestedBy = "", string CallerApp = "")
        {
            try
            {
                using (var ctx = new GRMSecurityEntities())
                {
                    ctx.RequestLogs.AddObject(new RequestLogs
                    {
                        RequestURL = $"{OperationContext.Current.EndpointDispatcher.EndpointAddress}/{RequestUrl}",
                        RequestedBy = RequestedBy,
                        CallerApplication = CallerApp,
                        DateTime = DateTime.Now
                    });
                    ctx.SaveChanges();
                }
            }
            catch (Exception ex)
            {

            }


        }
        public List<User_Key_Mapping> GetAllActiveUsers_Insights()
        {
            return GetAllActiveUsers();
        }

        //[return: MessageParameter(Name = "CreateCrowdToken")]
        public CrowdUserObj CreateCrowdTokenByUserName(string userName)
        {
            var response = AuthenticateUserFromCrowd_internal(userName, string.Empty, true);
            return response;
        }

        public string GetEmailAddressFromUserToken(string CrowdSSOToken)
        {
            string resEmail = string.Empty;
            Utilities.WriteTrace("Entering GetEmailAddressFromUserToken");
            try
            {
                Utilities.WriteTrace("Before GetEmailAddressFromUserToken");
                CrowdAuthenticationService obj = new CrowdAuthenticationService();
                return obj.GetEmailAddressFromUserToken(CrowdSSOToken);
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, ex.Message);
            }
            Utilities.WriteTrace("Exit GetEmailAddressFromUserToken");
            return resEmail;
        }

        public CrowdUserObj GetUserCrowdByEmail(string Email)
        {

            CrowdUserObj obj = null;
            if (String.IsNullOrEmpty(Email))
            {
                return obj;
            }

            string RemoteKey = String.Empty;
            string userName = String.Empty;
            using (GRM_Security_Entities ctx = new GRM_Security_Entities())
            {
                var query = ctx.Users.Where(x => x.Email != null).Where(y => y.Email.ToLower() == Email.ToLower()).FirstOrDefault();
                if (query != null)
                {
                    userName = query.UserName;
                    RemoteKey = query.UserRemoteKey.ToString();
                }
            }
            obj = AuthenticateUserFromCrowd_internal(userName, "", true);
            obj.RemoteKey = RemoteKey;
            return obj;
        }

    }
}