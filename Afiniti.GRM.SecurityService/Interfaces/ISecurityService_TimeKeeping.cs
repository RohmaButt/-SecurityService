using Afiniti.GRM.SecurityDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Web;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_TimeKeeping")]
    public interface ISecurityService_TimeKeeping
    {
        [OperationContract(Name = "Authenticate_TimeKeeping")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "Authenticate_TimeKeeping", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "Response")]
        SecurityDTO.UserDTO AuthenticateAndAuthorizeUser_TimeKeeping(AuthRequestModel model);

        [OperationContract(Name = "CrowdAuthenticate_TimeKeeping")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "CrowdAuthenticate_TimeKeeping", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "Response")]
        SecurityDTO.UserDTO CrowdAuthenticateAndAuthorizeUser_TimeKeeping(AuthRequestModel model);

        [OperationContract(Name = "Logout_TimeKeeping")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "Logout_TimeKeeping", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "LoggedOut")]
        bool Logout_TimeKeeping(string CrowdSSOToken);

        [OperationContract(Name = "IsUserAuthenticated_TimeKeeping")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "IsUserAuthenticated_TimeKeeping?token={CrowdSSOToken}")]
        [return: MessageParameter(Name = "Authenticated")]
        bool IsUserAuthenticated_TimeKeeping(string CrowdSSOToken);

        [OperationContract(Name = "CreateCrowdTokenByUserName_TimeKeeping")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "CreateCrowdTokenByUserName_TimeKeeping?username={userName}")]
        [return: MessageParameter(Name = "CreateCrowdToken")]
        CrowdUserObj CreateCrowdTokenByUserName_TimeKeeping(string userName);
    }
}