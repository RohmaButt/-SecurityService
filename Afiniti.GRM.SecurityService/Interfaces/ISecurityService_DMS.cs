using Afiniti.GRM.SecurityDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Web;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "ISecurityService_DMS")]
    public interface ISecurityService_DMS
    {
        [OperationContract]
        CrowdUserObjMobile AuthenticateUser_DMSMAC(string UserName, string Password,Guid AppKey);

        [OperationContract]
        bool SendApprovalRequestEmail_DMSMAC(string UserName, string Message);

        [OperationContract]
        bool Logout_DMSMAC(string CrowdSSOToken);
        
        [OperationContract]
        AppConfiguration GetAppConfig_DMSMAC(Guid appKey);

        [OperationContract]
        CrowdUserObj GetValidUserToken_DMSMAC(string crowd_ssoToken, string userName);

    }
}