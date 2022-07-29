using Afiniti.GRM.SecurityDTO;
using System.ServiceModel;
using System.ServiceModel.Web;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_AfinitiPortal")]
    public interface ISecurityService_AfinitiPortal
    {
        [OperationContract(Name = "GetUsersSecurityDataByToken_AfinitiPortal")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "GetUsersSecurityDataByToken_AfinitiPortal", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "Response")]
        UserDTO GetUsersSecurityDataByToken_AfinitiPortal(string CrowdSSOToken, string IPAddress);

        [OperationContract(Name = "AuthenticateAndAuthorizeByCrowd_AfinitiPortal")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "AuthenticateAndAuthorizeByCrowd_AfinitiPortal", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "Response")]
        CrowdUserObj AuthenticateAndAuthorizeByCrowd_AfinitiPortal(AuthRequestModel model);

        [OperationContract(Name = "AuthenticateUserByCrowd_AfinitiPortal")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "AuthenticateUserByCrowd_AfinitiPortal", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "Response")]
        CrowdUserObj AuthenticateUserByCrowd_AfinitiPortal(string CrowdSSOToken, string UserName);
    }
}