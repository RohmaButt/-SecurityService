using System.ServiceModel;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_JiraMobile")]
    public interface ISecurityService_JiraMobile
    {
        [OperationContract(Name = "AuthenticateUserJiraMobile")]
        CrowdUserObj AuthenticateUser_JiraMobile(string UserName, string Password);

        [OperationContract]
        void SendApprovalRequestEmailFromJiraMobile(string UserName, string Message);

        [OperationContract]
        bool LogoutFromJiraMobile(string CrowdSSOToken);

        [OperationContract]
        CrowdUserObj GetValidUserToken_JiraMobile(string crowd_ssoToken, string userName);

        [OperationContract]
        AppConfiguration GetJiraAppConfig(string appName);
    }
}