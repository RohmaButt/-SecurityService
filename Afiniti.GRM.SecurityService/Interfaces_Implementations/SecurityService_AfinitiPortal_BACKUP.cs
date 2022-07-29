using Afiniti.GRM.SecurityDTO;
using Afiniti.GRM.Shared;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_AfinitiPortal
    {
        //Get MenuPermissions from CrowdSSOToken for Afiniti Portal user
        public UserDTO GetUsersSecurityDataByToken_AfinitiPortal(string CrowdSSOToken, string IPAddress)
        {
            UserDTO recordObj = null;
            try
            {
                CrowdUserObj crowdUserObj = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (crowdUserObj != null)
                {
                    recordObj = GetUsersSecurityDataPortal(crowdUserObj.UserName, IPAddress);
                    recordObj.CrowdObj = new CrowdUserObj();
                    recordObj.CrowdObj.CrowdSSOToken = CrowdSSOToken;
                    recordObj.CrowdObj.JSessionID = crowdUserObj.JSessionID;
                    recordObj.CrowdObj.AuthenticationMetaData = EncryptionClass.Encrypt_Decrypt(ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" + crowdUserObj.JSessionID + ";" + ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" + crowdUserObj.CrowdSSOToken, true);
                    UserObj userObj = new UserObj();
                    CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"], ConfigurationManager.AppSettings["CrowdAppName"], ConfigurationManager.AppSettings["CrowdAppPass"]);

                    var fullUserObj = crowdService.GetUserFromCrowd(crowdUserObj.UserName);
                    if (fullUserObj != null && !String.IsNullOrEmpty(fullUserObj.DisplayName))
                    {
                        userObj.AvatarURL = fullUserObj.AvatarURL;
                        userObj.DisplayName = fullUserObj.DisplayName;
                    }
                    recordObj.userObj = userObj;
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return recordObj;
        }
        private SecurityDTO.UserDTO GetUsersSecurityDataPortal(string UserName, string IPAddress)
        {
            SecurityDTO.UserDTO data = null;
            try
            {
                string appKey = ConfigurationManager.AppSettings["AfinitiPortalAppKey"].ToString();
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    if (ctx.SecurityApps.Any(x => x.AppName.ToLower() == appKey) && ctx.Users.Any(x => x.UserName.ToLower() == UserName.ToLower()))
                    {
                        Utilities.WriteTrace("GetUsersSecurityDataPortal_Start_PermissionsQuery");
                        var query = (from user in ctx.Users
                                     join userRoles in ctx.UserRole_Rel on user.UserKey equals userRoles.UserKey
                                     join roles in ctx.Roles on userRoles.RoleKey equals roles.RoleKey
                                     where user.IsActive == true && roles.IsActive == true && userRoles.IsActive == true && user.UserName.ToLower() == UserName.ToLower()
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
                                         CanImpersonate = user.CanImpersonate,
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
                                                        select permissions).ToList()).OrderBy(s => s.SortOrder)
                                     }).FirstOrDefault();
                        UserDTO record = new UserDTO
                        {
                            RoleKey = query.RoleKey,
                            UserKey = query.UserKey,
                            RoleName = query.RoleName,
                            UserName = query.UserName,
                            ApprovalStatus = (int)query.ApprovalStatus,
                            UserRemoteKey = query.UserRemoteKey ?? Guid.Empty,
                            Email = query.Email,
                            OutlookGenieAttrMapping = query.MappingData,
                            IsAdmin = query.IsAdmin,
                            CanImpersonate = query.CanImpersonate,
                            Permissions = new List<Permission>()
                        };
                        foreach (var permission in query.Permissions)
                        {
                            Permission _permission = new Permission
                            {
                                ParentKey = permission.ParentKey,
                                Name = permission.Name,
                                PermissionKey = permission.PermissionKey,
                                TypeKey = permission.PermissionTypeKey,
                                Key = permission.Key,
                                URL = permission.URL,
                                CssClass = permission.CSSClass,
                                DisplayText = permission.DisplayText,
                                SortOrder = permission.SortOrder,
                                AdminLevel = false
                            };
                            record.Permissions.Add(_permission);
                        }
                        Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start_PermissionsQuery_WIP");
                        //CrowdUserObj crowdObj = new CrowdUserObj();
                        //UserObj userObj = new UserObj
                        //{
                        //    AvatarURL = authResponse.UserAvatarUrl,
                        //    DisplayName = authResponse.UserDisplayName
                        //};
                        //crowdObj.CrowdSSOToken = authResponse.CrowdSSOToken;
                        //crowdObj.JSessionID = authResponse.JSessionID;
                        //record.CrowdObj = crowdObj;
                        //record.userObj = userObj;
                        data = record;
                        data.LoggedInFromNewIP = !ctx.UserSessions.Where(x => x.IPAddress == IPAddress).Any();
                        Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Exit");
                    }
                    else
                    {
                        UserDTO record = new UserDTO
                        {
                            UserName = UserName,
                            ApprovalStatus = (int)ApprovalStatus.PendingForApproval
                        };
                        data = record;
                        Utilities.WriteTrace("GetUsersSecurityDataPortal_ElseAppNameIssue");
                    }
                }
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "");
            }
            return data;
        }

        //Authenticate and Authorize requested APIController for AfinitiPortal user
        public UserDTO AuthenticateAndAuthorizeByCrowd_AfinitiPortal(AuthRequestModel model)
        {
            if (String.IsNullOrEmpty(model.UserName) || string.IsNullOrEmpty(model.Password))
            {
                return null;
            }
            UserDTO data = null;
            try
            {
                Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start");

                string appKey = ConfigurationManager.AppSettings["AfinitiPortalAppKey"].ToString();
                AuthResponseModel authResponse = AuthenticateUser_TimeKeeping(model.UserName, model.Password);
                Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start_authResponse");

                //if (authResponse.CrowdSSOToken == null)
                //{
                //    CrowdUserObj userObj1 = CreateCrowdTokenByUserName(model.UserName);
                //    authResponse.CrowdSSOToken = userObj1.CrowdSSOToken;
                //    authResponse.JSessionID = userObj1.JSessionID;
                //    authResponse.UserAvatarUrl = "";
                //    authResponse.UserDisplayName = userObj1.UserName;
                //}
                authResponse.IsAuthenticated = true;
                //  authResponse.UserName = "rohma.butt";
                //authResponse.ApprovalStatus = 0;
                //authResponse.AuthenticationCode = 1;
                authResponse.CrowdSSOToken = "gvChF5w33q9J6PpsXAd7TQ00";
                //authResponse.Email = null;
                authResponse.JSessionID = "4DEF73D84731BBFA0D314EEB720459A";
                //authResponse.RemoteKey = null;
                //authResponse.UserKey = null;
                //authResponse.UserName = "rohma.butt";

                if (authResponse != null)
                {
                    Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start_authResponse!=null");
                    if (authResponse.IsAuthenticated)
                    {
                        Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start_authResponse.IsAuthenticated");
                        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                        {
                            if (ctx.SecurityApps.Any(x => x.AppName.ToLower() == appKey))// && ctx.Users.Any(x => x.UserName.ToLower() == model.UserName.ToLower()))
                            {
                                //Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start_PermissionsQuery");
                                //var query = (from user in ctx.Users
                                //             join userRoles in ctx.UserRole_Rel on user.UserKey equals userRoles.UserKey
                                //             join roles in ctx.Roles on userRoles.RoleKey equals roles.RoleKey
                                //             where user.IsActive == true && roles.IsActive == true && userRoles.IsActive == true && user.UserName.ToLower() == model.UserName.ToLower()
                                //             select new
                                //             {
                                //                 UserName = user.UserName,
                                //                 RoleName = roles.Name,
                                //                 RoleKey = roles.RoleKey,
                                //                 UserKey = user.UserKey,
                                //                 ApprovalStatus = user.ApprovalStatus,
                                //                 UserRemoteKey = user.UserRemoteKey,
                                //                 Email = user.Email,
                                //                 IsAdmin = user.IsAdmin,
                                //                 CanImpersonate = user.CanImpersonate,
                                //                 MappingData = user.OutlookGenieAttrMapping,
                                //                 Permissions = (
                                //                                from AppPermAssignment in ctx.ApplicationPermission_Assignment
                                //                                join permissions in ctx.Permissions on AppPermAssignment.PermissionKey equals permissions.PermissionKey
                                //                                join Apps in ctx.SecurityApps on AppPermAssignment.AppKey equals Apps.AppKey
                                //                                where permissions.IsActive == true && AppPermAssignment.IsActive == true && Apps.AppName.ToLower() == appKey
                                //                                select permissions).Intersect(
                                //                                    (
                                //                                from permAssignment in ctx.UserPermission_Assignment
                                //                                join permissions in ctx.Permissions on permAssignment.PermissionKey equals permissions.PermissionKey
                                //                                where permAssignment.UserKey == user.UserKey && permissions.IsActive == true && permAssignment.IsActive == true
                                //                                select permissions).ToList()).OrderBy(s => s.SortOrder)
                                //             }).FirstOrDefault();
                                UserDTO record = new UserDTO
                                {
                                    //RoleKey = query.RoleKey,
                                    //UserKey = query.UserKey,
                                    //RoleName = query.RoleName,
                                    //UserName = query.UserName,
                                    //ApprovalStatus = (int)query.ApprovalStatus,
                                    //UserRemoteKey = query.UserRemoteKey ?? Guid.Empty,
                                    //Email = query.Email,
                                    //OutlookGenieAttrMapping = query.MappingData,
                                    //IsAdmin = query.IsAdmin,
                                    //CanImpersonate = (bool)query.CanImpersonate,
                                    //    Permissions = new List<Permission>()
                                };
                                //foreach (var permission in query.Permissions)
                                //{
                                //    Permission _permission = new Permission
                                //    {
                                //        ParentKey = permission.ParentKey,
                                //        Name = permission.Name,
                                //        PermissionKey = permission.PermissionKey,
                                //        TypeKey = permission.PermissionTypeKey,
                                //        Key = permission.Key,
                                //        URL = permission.URL,
                                //        CssClass = permission.CSSClass,
                                //        DisplayText = permission.DisplayText,
                                //        SortOrder = permission.SortOrder,
                                //        AdminLevel = false
                                //    };
                                //    record.Permissions.Add(_permission);
                                //}
                                Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Start_PermissionsQuery_WIP");
                                CrowdUserObj crowdObj = new CrowdUserObj();
                                UserObj userObj = new UserObj
                                {
                                    AvatarURL = authResponse.UserAvatarUrl,
                                    DisplayName = authResponse.UserDisplayName
                                };
                                crowdObj.CrowdSSOToken = authResponse.CrowdSSOToken;
                                crowdObj.JSessionID = authResponse.JSessionID;
                                record.CrowdObj = crowdObj;
                                record.userObj = userObj;
                                data = record;
                                //data.LoggedInFromNewIP = !ctx.UserSessions.Where(x => x.IPAddress == model.IPAddress).Any();
                                Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_Exit");
                            }
                            else
                            {
                                UserDTO record = new UserDTO
                                {
                                    UserName = model.UserName,
                                    ApprovalStatus = (int)ApprovalStatus.PendingForApproval
                                };
                                data = record;
                                Utilities.WriteTrace("AuthenticateAndAuthorizeByCrowd_AfinitiPortal_ElseAppNameIssue");
                            }
                        }
                    }
                    else
                    {
                        UserDTO record = new UserDTO
                        {
                            UserName = model.UserName,
                            ApprovalStatus = (int)ApprovalStatus.PendingForApproval
                        };
                        data = record;
                    }
                }
                else
                {
                    UserDTO record = new UserDTO
                    {
                        UserName = model.UserName,
                        ApprovalStatus = (int)ApprovalStatus.PendingForApproval
                    };
                    data = record;
                }
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "Exception_TimeKeeping");
            }
            return data;
        }
        public CrowdUserObj AuthenticateUserByCrowd_AfinitiPortal(string CrowdSSOToken, string UserName)
        {
            CrowdUserObj authResponse = new CrowdUserObj()
            {
                AuthenticationMetaData = "Crowd validation failed. CrowdSSOToken or UserName is missing",
                AuthenticationCode = 0,
                CrowdSSOToken = CrowdSSOToken,
                UserName = UserName,
                Email = null,
                JSessionID = null
            };
            if (string.IsNullOrEmpty(CrowdSSOToken) || string.IsNullOrEmpty(UserName))
                return authResponse;
            try
            {
                CrowdUserObj crowdObj = new CrowdUserObj();
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"], ConfigurationManager.AppSettings["CrowdAppName"], ConfigurationManager.AppSettings["CrowdAppPass"]);
                Utilities.WriteTrace("AuthenticateUserByCrowd_AfinitiPortal_Start");
                authResponse = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (authResponse != null)
                {
                    Utilities.WriteTrace("enter. AuthenticateUserByCrowd_AfinitiPortal.UserName:::" + authResponse.UserName, authResponse.CrowdSSOToken, authResponse.JSessionID);
                    if (authResponse != null && !string.IsNullOrEmpty(authResponse.UserName) && !string.IsNullOrEmpty(authResponse.JSessionID))//Token is valid
                    {
                        Utilities.WriteTrace("AuthenticateUserByCrowd_AfinitiPortal_Exit:authResponse.UserName or JSessionID  is returned");
                        authResponse.AuthenticationMetaData = "Authentication passed. Valid token is returned";
                        authResponse.AuthenticationCode = 1;
                        authResponse.CrowdSSOToken = CrowdSSOToken;
                        authResponse.UserName = authResponse.UserName;
                        authResponse.Email = GetEmailAddressFromUserToken(CrowdSSOToken);
                        authResponse.JSessionID = authResponse.JSessionID;
                        Utilities.WriteTrace("AuthenticateUserByCrowd_AfkinitiPortal_Start_Exit");
                    }
                    else
                    {
                        Utilities.WriteTrace("AuthenticateUserByCrowd_AfinitiPortal_Exit:authResponse.UserName or JSessionID is null so refreshing token");
                        crowdObj = CreateCrowdTokenByUserName(UserName);
                        authResponse.AuthenticationMetaData = "Authentication passed. Fresh token is returned";
                        authResponse.AuthenticationCode = 1;
                        authResponse.CrowdSSOToken = crowdObj.CrowdSSOToken;
                        authResponse.UserName = crowdObj.UserName;
                        authResponse.Email = GetEmailAddressFromUserToken(crowdObj.CrowdSSOToken);
                        authResponse.JSessionID = crowdObj.JSessionID;
                    }
                }
                else
                {
                    Utilities.WriteTrace("AuthenticateUserByCrowd_AfinitiPortal_Exit:authResponse is null so refreshing token");
                    crowdObj = CreateCrowdTokenByUserName(UserName);
                    authResponse.AuthenticationMetaData = "Authentication passed. Fresh token is returned";
                    authResponse.AuthenticationCode = 1;
                    authResponse.CrowdSSOToken = crowdObj.CrowdSSOToken;
                    authResponse.UserName = crowdObj.UserName;
                    authResponse.Email = GetEmailAddressFromUserToken(crowdObj.CrowdSSOToken);
                    authResponse.JSessionID = crowdObj.JSessionID;
                }
            }
            catch (Exception exc)
            {
                authResponse.AuthenticationMetaData = "Authentication failed. Please check BI team or try again";
                authResponse.AuthenticationCode = 0;
                authResponse.CrowdSSOToken = CrowdSSOToken;
                authResponse.UserName = UserName;
                authResponse.Email = null;
                authResponse.JSessionID = null;
                Utilities.LogException(exc, "Exception_AuthenticateUserByCrowd_AfinitiPortal");
            }
            return authResponse;
        }
    }
}