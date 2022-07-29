using Afiniti.GRM.SecurityDTO;
using Afiniti.GRM.Shared;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel;
using System.Web;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_TimeKeeping
    {
        public SecurityDTO.UserDTO AuthenticateAndAuthorizeUser_TimeKeeping(AuthRequestModel model/*string UserName, string Password, string IPAddress*/)
        {
            if (String.IsNullOrEmpty(model.UserName) || string.IsNullOrEmpty(model.Password) || string.IsNullOrEmpty(model.IPAddress))
            {
                return null;
            }
            SecurityDTO.UserDTO data = null;
            try
            {
                Utilities.WriteTrace("AuthenticateUser_Start");

                string appKey = ConfigurationManager.AppSettings["TimeKeepingAppKey"].ToString();
                AuthResponseModel authResponse = AuthenticateUser_TimeKeeping(model.UserName, model.Password);
                if (authResponse != null)
                {
                    if (authResponse.IsAuthenticated)
                    {
                        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                        {
                            if (ctx.SecurityApps.Any(x => x.AppName.ToLower() == appKey) && ctx.Users.Any(x => x.UserName.ToLower() == model.UserName.ToLower()))
                            {
                                var query = (from user in ctx.Users
                                             join userRoles in ctx.UserRole_Rel on user.UserKey equals userRoles.UserKey
                                             join roles in ctx.Roles on userRoles.RoleKey equals roles.RoleKey
                                             where user.IsActive == true && roles.IsActive == true && userRoles.IsActive == true && user.UserName.ToLower() == model.UserName.ToLower()
                                             select new
                                             {
                                                 UserName = user.UserName,
                                                 RoleName = roles.Name,
                                                 RoleKey = roles.RoleKey,
                                                 UserKey = user.UserKey,
                                                 ApprovalStatus = user.ApprovalStatus,
                                                 UserRemoteKey = user.UserRemoteKey,
                                                 Email = user.Email,
                                                 IsAdmin = user.IsAdmin,
                                                 MappingData = user.OutlookGenieAttrMapping,
                                                 Permissions = (
                                                                from AppPermAssignment in ctx.ApplicationPermission_Assignment
                                                                join permissions in ctx.Permissions on AppPermAssignment.PermissionKey equals permissions.PermissionKey
                                                                join Apps in ctx.SecurityApps on AppPermAssignment.AppKey equals Apps.AppKey
                                                                where permissions.IsActive == true && AppPermAssignment.IsActive == true && Apps.AppName.ToLower() == appKey
                                                                select permissions).Intersect(
                                                                    (
                                                                from permAssignment in ctx.UserPermission_Assignment
                                                                join permissions in ctx.Permissions on permAssignment.PermissionKey equals permissions.PermissionKey
                                                                where permAssignment.UserKey == user.UserKey && permissions.IsActive == true && permAssignment.IsActive == true
                                                                select permissions).ToList())
                                             }).FirstOrDefault();
                                SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                                record.RoleKey = query.RoleKey;
                                record.UserKey = query.UserKey;
                                record.RoleName = query.RoleName;
                                record.UserName = query.UserName;
                                record.ApprovalStatus = (int)query.ApprovalStatus;
                                record.UserRemoteKey = query.UserRemoteKey ?? Guid.Empty;
                                record.Email = query.Email;
                                record.OutlookGenieAttrMapping = query.MappingData;
                                record.IsAdmin = query.IsAdmin;
                                record.Permissions = new List<SecurityDTO.Permission>();
                                foreach (var permission in query.Permissions)
                                {
                                    SecurityDTO.Permission _permission = new SecurityDTO.Permission();
                                    _permission.PermissionKey = permission.PermissionKey;
                                    _permission.TypeKey = permission.PermissionTypeKey;
                                    _permission.Key = permission.Key;
                                    _permission.URL = permission.URL;
                                    _permission.CssClass = permission.CSSClass;
                                    _permission.DisplayText = permission.DisplayText;
                                    _permission.SortOrder = permission.SortOrder;
                                    _permission.AdminLevel = false;
                                    record.Permissions.Add(_permission);
                                }
                                SecurityDTO.CrowdUserObj crowdObj = new SecurityDTO.CrowdUserObj();
                                SecurityDTO.UserObj userObj = new SecurityDTO.UserObj();
                                userObj.AvatarURL = authResponse.UserAvatarUrl;
                                userObj.DisplayName = authResponse.UserDisplayName;
                                crowdObj.CrowdSSOToken = authResponse.CrowdSSOToken;
                                crowdObj.JSessionID = authResponse.JSessionID;
                                record.CrowdObj = crowdObj;
                                record.userObj = userObj;
                                data = record;
                                data.LoggedInFromNewIP = !ctx.UserSessions.Where(x => x.IPAddress == model.IPAddress).Any();
                                Utilities.WriteTrace("Security_Service_TimeKeeping_Exit");
                            }
                            else
                            {
                                SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                                record.UserName = model.UserName;
                                record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                                data = record;
                            }
                        }
                    }
                    else
                    {
                        SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                        record.UserName = model.UserName;
                        record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                        data = record;
                    }
                }
                else
                {
                    SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                    record.UserName = model.UserName;
                    record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                    data = record;
                }
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "Exception_TimeKeeping");
            }
            return data;
        }

        public SecurityDTO.UserDTO CrowdAuthenticateAndAuthorizeUser_TimeKeeping(AuthRequestModel model)
        {
            if (String.IsNullOrEmpty(model.CrowdSSOToken))
            {
                return null;
            }
            SecurityDTO.UserDTO data = null;
            try
            {
                Utilities.WriteTrace("CrowdAuthenticateUser_Start");
                string appKey = ConfigurationManager.AppSettings["TimeKeepingAppKey"].ToString();
                CrowdUserObj authResponse = GetUserObjectFromCrowdToken(model.CrowdSSOToken);
                if (authResponse != null)
                {
                    if (authResponse != null && !string.IsNullOrEmpty(authResponse.UserName))// authResponse.ApprovalStatus == 2 && authResponse.AuthenticationCode == 1)//get permissions for user
                    {
                        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                        {
                            if (ctx.SecurityApps.Any(x => x.AppName.ToLower() == appKey) && ctx.Users.Any(x => x.UserName.ToLower() == authResponse.UserName.ToLower()))
                            {
                                var query = (from user in ctx.Users
                                             join userRoles in ctx.UserRole_Rel on user.UserKey equals userRoles.UserKey
                                             join roles in ctx.Roles on userRoles.RoleKey equals roles.RoleKey
                                             where user.IsActive == true && roles.IsActive == true && userRoles.IsActive == true && user.UserName.ToLower() == authResponse.UserName.ToLower()
                                             select new
                                             {
                                                 UserName = user.UserName,
                                                 RoleName = roles.Name,
                                                 RoleKey = roles.RoleKey,
                                                 UserKey = user.UserKey,
                                                 ApprovalStatus = user.ApprovalStatus,
                                                 UserRemoteKey = user.UserRemoteKey,
                                                 Email = user.Email,
                                                 IsAdmin = user.IsAdmin,
                                                 MappingData = user.OutlookGenieAttrMapping,
                                                 Permissions = (
                                                                from AppPermAssignment in ctx.ApplicationPermission_Assignment
                                                                join permissions in ctx.Permissions on AppPermAssignment.PermissionKey equals permissions.PermissionKey
                                                                join Apps in ctx.SecurityApps on AppPermAssignment.AppKey equals Apps.AppKey
                                                                where permissions.IsActive == true && AppPermAssignment.IsActive == true && Apps.AppName.ToLower() == appKey
                                                                select permissions).Intersect(
                                                                    (
                                                                from permAssignment in ctx.UserPermission_Assignment
                                                                join permissions in ctx.Permissions on permAssignment.PermissionKey equals permissions.PermissionKey
                                                                where permAssignment.UserKey == user.UserKey && permissions.IsActive == true && permAssignment.IsActive == true
                                                                select permissions).ToList())
                                             }).FirstOrDefault();
                                SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                                record.RoleKey = query.RoleKey;
                                record.UserKey = query.UserKey;
                                record.RoleName = query.RoleName;
                                record.UserName = query.UserName;
                                record.ApprovalStatus = (int)query.ApprovalStatus;
                                record.UserRemoteKey = query.UserRemoteKey ?? Guid.Empty;
                                record.Email = query.Email;
                                record.OutlookGenieAttrMapping = query.MappingData;
                                record.IsAdmin = query.IsAdmin;
                                record.Permissions = new List<SecurityDTO.Permission>();
                                foreach (var permission in query.Permissions)
                                {
                                    SecurityDTO.Permission _permission = new SecurityDTO.Permission();
                                    _permission.PermissionKey = permission.PermissionKey;
                                    _permission.TypeKey = permission.PermissionTypeKey;
                                    _permission.Key = permission.Key;
                                    _permission.URL = permission.URL;
                                    _permission.CssClass = permission.CSSClass;
                                    _permission.DisplayText = permission.DisplayText;
                                    _permission.SortOrder = permission.SortOrder;
                                    _permission.AdminLevel = false;
                                    record.Permissions.Add(_permission);
                                }
                                SecurityDTO.CrowdUserObj crowdObj = new SecurityDTO.CrowdUserObj();
                                SecurityDTO.UserObj userObj = new SecurityDTO.UserObj();
                                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                        ConfigurationManager.AppSettings["CrowdAppName"],
                        ConfigurationManager.AppSettings["CrowdAppPass"]);

                                var fullUserObj = crowdService.GetUserFromCrowd(authResponse.UserName);
                                if (fullUserObj != null && !String.IsNullOrEmpty(fullUserObj.DisplayName))
                                {
                                    userObj.AvatarURL = fullUserObj.AvatarURL;
                                    userObj.DisplayName = fullUserObj.DisplayName;
                                }
                                crowdObj.CrowdSSOToken = model.CrowdSSOToken;
                                crowdObj.JSessionID = authResponse.JSessionID;
                                record.CrowdObj = crowdObj;
                                record.userObj = userObj;
                                data = record;
                                data.LoggedInFromNewIP = !ctx.UserSessions.Where(x => x.IPAddress == model.IPAddress).Any();
                                Utilities.WriteTrace("CrowdSecurity_Service_TimeKeeping_Exit");
                            }
                            else
                            {
                                SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                                record.UserName = authResponse.UserName;
                                record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                                data = record;
                                Utilities.WriteTrace("CrowdAuthenticateUser_Exit:IssueinApp");

                            }
                        }
                    }
                    else
                    {
                        SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                        record.UserName = authResponse.UserName;
                        record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                        data = record; Utilities.WriteTrace("CrowdAuthenticateUser_Exit:IssueinCrowd");

                    }
                }
                else
                {
                    SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                    record.UserName = authResponse.UserName;
                    record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                    data = record;
                    data = record; Utilities.WriteTrace("CrowdAuthenticateUser_Exit:IssueinCrowdResponse");
                }
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "Exception_CrowdTimeKeepingAuthntication");
            }
            return data;
        }

        public AuthResponseModel AuthenticateUser_TimeKeeping(string UserName, string Password)
        {
            AuthResponseModel res = null;
            Utilities.WriteTrace("AuthenticateUser_TimeKeeping");
            try
            {
                if (!String.IsNullOrEmpty(UserName) && !String.IsNullOrEmpty(Password))
                {
                    LogRequest("AuthenticateUser", UserName, "TimeKeeping");
                    res = new AuthResponseModel();
                    var crowdUser = AuthenticateUserFromCrowd(UserName, Password);
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
                        var fullUserObj = crowdService.GetUserFromCrowd(UserName);
                        if (fullUserObj != null && !String.IsNullOrEmpty(fullUserObj.DisplayName))
                        {
                            res.UserDisplayName = fullUserObj.DisplayName;
                            res.UserAvatarUrl = fullUserObj.AvatarURL;
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
                    LogRequest("AuthenticateUser", "-NoAutenticatedUser-", "TimeKeeping");
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

            Utilities.WriteTrace("Exit AuthenticateUser_TimeKeeping");
            return res;
        }

        public bool IsUserAuthenticated_TimeKeeping(string CrowdSSOToken)
        {
            bool res = false;
            Utilities.WriteTrace("Entering IsUserAuthenticated_TK");
            try
            {
                CrowdUserObj obj = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (obj != null)
                {
                    if (String.IsNullOrEmpty(obj.UserName))
                    {
                        res = false;
                        LogRequest("IsUserAuthenticated", "-NoAutenticatedUser-", "TimeKeeping");
                    }
                    else
                    {
                        res = true;
                        LogRequest("IsUserAuthenticated", obj.UserName, "TimeKeeping");
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
            Utilities.WriteTrace("Exit IsUserAuthenticated_TimeKeeping");
            return res;
        }

        public bool Logout_TimeKeeping(string CrowdSSOToken)
        {
            bool loggedOut = false;
            Utilities.WriteTrace("Entering Logout_TimeKeeping");
            LogRequest("Logout", "-NoAutenticatedUser-", "TimeKeeping");
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
            Utilities.WriteTrace("Exit Logout_TimeKeeping");
            return loggedOut;
        }

        //For API use
        public CrowdUserObj CreateCrowdTokenByUserName_TimeKeeping(string userName)
        {
            var response = AuthenticateUserFromCrowd_internal(userName, string.Empty, true);
            return response;
        }
    }
}