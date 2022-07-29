using Afiniti.GRM.SecurityDTO;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_GenieFinancials
    {
        public CrowdUserObj AuthenticateUser_GenieFinancials(string UserName, string Password)
        {
            Utilities.WriteTrace("Entering AuthenticateUser_GenieFinancials");
            CrowdUserObj obj = null;
            try
            {
                obj = AuthenticateUserFromCrowdFor_GenieFinancials(UserName, Password);
                if (obj != null)
                {
                    if (String.IsNullOrEmpty(obj.UserName))
                    {
                        Utilities.WriteTrace("AuthenticateUser_GenieFinancials obj is null");
                        LogRequest("AuthenticateUser", "-NoAutenticatedUser-", "GenieFinancials");
                    }
                    else
                    {
                        Utilities.WriteTrace("AuthenticateUser_GenieFinancials is valid");
                        LogRequest("AuthenticateUser", obj.UserName, "GenieFinancials");
                    }
                }
                else
                {
                    Utilities.WriteTrace("Entering AuthenticateUser_GenieFinancials obj isnull");
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                Utilities.WriteTrace("Entering AuthenticateUser_GenieFinancials");
            }
            Utilities.WriteTrace("Exit AuthenticateUser_GenieFinancials");
            return obj;
        }

        public bool IsUserAuthenticated_GenieFinancials(string CrowdSSOToken)
        {
            bool res = false;
            Utilities.WriteTrace("Entering IsUserAuthenticated_GenieFinancials");
            try
            {
                CrowdUserObj obj = GetUserObjectFromCrowdToken(CrowdSSOToken);
                if (obj != null)
                {
                    if (String.IsNullOrEmpty(obj.UserName))
                    {
                        res = false;
                        LogRequest("IsUserAuthenticated", "-NoAutenticatedUser-", "GenieFinancials");
                    }
                    else
                    {
                        res = true;
                        LogRequest("IsUserAuthenticated", obj.UserName, "GenieFinancials");
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
            Utilities.WriteTrace("Exit IsUserAuthenticated_GenieFinancials");
            return res;
        }
    }
}