using System.ServiceModel;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_GenieMobile")]
    public interface ISecurityService_GenieMobile
    {
        [OperationContract(Name = "AuthenticateUserGenieMobile")]
        CrowdUserObj AuthenticateUser_GenieMobile(string UserName, string Password);

        [OperationContract(Name = "GetUserRemoteKeyByEmail")]
        CrowdUserObj GetUserRemoteKeyByEmail(string email);

        [OperationContract]
        void SendApprovalRequestEmailFromGenieMobile(string UserName, string Message);

        [OperationContract]
        bool LogoutFromGenieMobile(string CrowdSSOToken);

        [OperationContract]
        AppConfiguration GetGenieAppConfig_IOS();
    }
}