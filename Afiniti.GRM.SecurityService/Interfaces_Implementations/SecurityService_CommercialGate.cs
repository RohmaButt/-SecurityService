using Afiniti.GRM.SecurityDTO;
using Afiniti.GRM.Shared;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_CommercialGate
    {
        //Get Genie MenuPermissions from CrowdSSOToken for CG user
        public UserDTO GetUsersSecurityDataByToken_CG(string CrowdToken, string IPAddress)
        {
            return GetUsersSecurityDataByToken(CrowdToken, IPAddress);
        }

        //Authenticate and Authorize requested APIController for CG user
        public UserDTO AuthenticateAndAuthorizeByCrowd_CG(string CrowdSSOToken, string IPAddress, string ControllerPath)
        {
            if (String.IsNullOrEmpty(ControllerPath) || String.IsNullOrEmpty(CrowdSSOToken))
            {
                return null;
            }
            UserDTO data = null;
            CrowdUserObj crowdObj = new CrowdUserObj();
            try
            {
                Utilities.WriteTrace("CrowdAuthenticate_CGUser_Start");
                string appKey = ConfigurationManager.AppSettings["GenieAppKey"].ToString();
                CrowdUserObj authResponse = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (authResponse != null)
                {
                    Utilities.WriteTrace("enter. authResponse.UserName" + authResponse.UserName);
                    if (authResponse != null && !string.IsNullOrEmpty(authResponse.UserName))//get permissions for user
                    {
                        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                        {
                            Utilities.WriteTrace("enter. ControllerPath-" + ControllerPath);
                            Utilities.WriteTrace("enter. SSO" + CrowdSSOToken);
                            if (ctx.Users.Where(x => x.UserName.ToLower() == authResponse.UserName.ToLower()).Select(x => x).FirstOrDefault().ApprovalStatus == (int)ApprovalStatus.Approved)
                            {
                                Utilities.WriteTrace("enter. before query ");
                                var query = (from user in ctx.Users
                                             join userRoles in ctx.UserRole_Rel on user.UserKey equals userRoles.UserKey
                                             join roles in ctx.Roles on userRoles.RoleKey equals roles.RoleKey
                                             where user.IsActive == true && roles.IsActive == true && userRoles.IsActive == true && user.UserName.ToLower() == authResponse.UserName.ToLower()
                                             select new
                                             {
                                                 Permissions = (
                                                                from AppPermAssignment in ctx.ApplicationPermission_Assignment
                                                                join permissions in ctx.Permissions on AppPermAssignment.PermissionKey equals permissions.PermissionKey
                                                                join Apps in ctx.SecurityApps on AppPermAssignment.AppKey equals Apps.AppKey
                                                                where permissions.IsActive == true && AppPermAssignment.IsActive == true && Apps.AppName.ToLower() == appKey
                                                                && permissions.URL.ToLower() == ControllerPath.ToLower()
                                                                select permissions).Intersect(
                                                                    (
                                                                from permAssignment in ctx.UserPermission_Assignment
                                                                join permissions in ctx.Permissions on permAssignment.PermissionKey equals permissions.PermissionKey
                                                                where permAssignment.UserKey == user.UserKey && permissions.IsActive == true && permAssignment.IsActive == true
                                                                select permissions).ToList())
                                             }).FirstOrDefault();
                                Utilities.WriteTrace("enter. after query");
                                UserDTO record = new SecurityDTO.UserDTO
                                {
                                    Permissions = new List<SecurityDTO.Permission>()
                                };
                                foreach (var permission in query.Permissions)
                                {
                                    Permission _permission = new SecurityDTO.Permission
                                    {
                                        Key = permission.Key,
                                        URL = permission.URL,
                                        AdminLevel = false
                                    };
                                    record.Permissions.Add(_permission);
                                }
                                Utilities.WriteTrace("enter. permiss in between-");
                                var queryPermissions = (from permTemplate in ctx.RolePermission_Template
                                                        join perm in ctx.Permissions on permTemplate.PermissionKey equals perm.PermissionKey
                                                        where permTemplate.RoleKey == RoleTypes.Admin.Value && permTemplate.IsActive == true && perm.IsActive == true
                                                         && perm.URL.ToLower() == ControllerPath.ToLower()
                                                        select perm).ToList();
                                foreach (var permission in queryPermissions)
                                {
                                    Permission _permission = new SecurityDTO.Permission
                                    {
                                        Key = permission.Key,
                                        URL = permission.URL,
                                        AdminLevel = true
                                    };
                                    if (record.IsAdmin == true)
                                    {
                                        record.Permissions.Add(_permission);
                                    }
                                    else if (record.Permissions.Any(x => x.PermissionKey == _permission.PermissionKey))
                                    {
                                        Utilities.WriteTrace("Removing Permission with Name : " + permission.Name);
                                        record.Permissions.RemoveAll(x => x.PermissionKey == _permission.PermissionKey);
                                    }
                                }
                                Utilities.WriteTrace("enter. permiss almost" + record.Permissions.Count);
                                data = record;
                                data.CrowdObj = authResponse;
                                data.LoggedInFromNewIP = !ctx.UserSessions.Where(x => x.IPAddress == IPAddress).Any();
                                Utilities.WriteTrace("enter. permiss almost end");
                            }
                            else
                            {
                                Utilities.WriteTrace("enter. ctx.Users.Where fails");
                                UserDTO record = new SecurityDTO.UserDTO();
                                data = record;
                                data.CrowdObj = authResponse;
                            }
                        }
                        Utilities.WriteTrace("enter. permiss ends");
                    }
                    else
                    {
                        UserDTO record = new SecurityDTO.UserDTO();
                        data.CrowdObj = authResponse;
                        data = record; Utilities.WriteTrace("CrowdAuthenticate_CGUser_Exit:IssueinCrowd");
                    }
                }
                else
                {
                    UserDTO record = new SecurityDTO.UserDTO();
                    data = record;
                    data.CrowdObj = authResponse;
                    data = record; Utilities.WriteTrace("CrowdAuthenticate_CGUser_Exit:IssueinCrowdResponse");
                }
                Utilities.WriteTrace("enter. try ends");
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "Exception_Crowd_CGAuthentication");
            }
            Utilities.WriteTrace("enter. before return" + data);
            return data;
        }

        //Authenticate of CG user
        public CrowdUserObj AuthenticateUserByCrowd_CG(string CrowdSSOToken)
        {
            if (String.IsNullOrEmpty(CrowdSSOToken))
            {
                return null;
            }
            CrowdUserObj authResponse = null;
            try
            {
                Utilities.WriteTrace("AuthenticateUserByCrowd_CG_Start");
                string appKey = ConfigurationManager.AppSettings["GenieAppKey"].ToString();
                authResponse = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (authResponse != null)
                {
                    Utilities.WriteTrace("enter. AuthenticateUserByCrowd_CG.UserName" + authResponse.UserName);
                    if (authResponse != null && !string.IsNullOrEmpty(authResponse.UserName) && !string.IsNullOrEmpty(authResponse.JSessionID))
                    {
                        Utilities.WriteTrace("AuthenticateUserByCrowd_CG_Exit:authResponse.UserName or JSessionID  is returned");
                        // return authResponse;
                    }
                    else
                    {
                        Utilities.WriteTrace("AuthenticateUserByCrowd_CG_Exit:authResponse.UserName or JSessionID is null");
                        authResponse.AuthenticationMetaData = "Authentication failed. Please check your credentials and try again";
                        authResponse.UserName = null;
                        authResponse.JSessionID = null;
                    }
                }
                else
                {
                    Utilities.WriteTrace("AuthenticateUserByCrowd_CG_Exit:authResponse is null");
                    authResponse.AuthenticationMetaData = "Authentication failed. Please check your credentials and try again";
                    authResponse.UserName = null;
                    authResponse.JSessionID = null;
                    //return null;
                }
                //return authResponse;
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "Exception_AuthenticateUserByCrowd_CG");
            }
            return authResponse;
        }

    }
}