using System.ServiceModel;
using System.ServiceModel.Web;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_GenieFinancials")]
    public interface ISecurityService_GenieFinancials
    {
        [OperationContract(Name = "AuthenticateUserGenieFinancials")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "AuthenticateUserGenieFinancials?UserName={UserName}&Password={Password}")]
        [return: MessageParameter(Name = "Response")]
        CrowdUserObj AuthenticateUser_GenieFinancials(string UserName, string Password);

        [OperationContract(Name = "IsUserAuthenticated_GenieFinancials")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "IsUserAuthenticated_GenieFinancials?CrowdSSOToken={CrowdSSOToken}")]
        [return: MessageParameter(Name = "Response")]
        bool IsUserAuthenticated_GenieFinancials(string CrowdSSOToken);

    }
}