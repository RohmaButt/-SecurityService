using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Web;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_Insights")]
    public interface ISecurityService_Insights
    {
        [OperationContract(Name = "Authenticate")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "Authenticate", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "Response")]
        //DataModel<AuthResponseModel> AuthenticateUser_Insights(AuthRequestModel model);
        AuthResponseModel AuthenticateUser_Insights(AuthRequestModel model);

        [OperationContract(Name = "Logout")]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "Logout", BodyStyle = WebMessageBodyStyle.Wrapped)]
        [return: MessageParameter(Name = "LoggedOut")]
        bool Logout_Insights(string CrowdSSOToken);

        [OperationContract(Name = "IsUserAuthenticated")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "IsUserAuthenticated?token={CrowdSSOToken}")]
        [return: MessageParameter(Name = "Authenticated")]
        bool IsUserAuthenticated(string CrowdSSOToken);

        [OperationContract(Name = "GetAllUsers")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "GetAllActiveUsers")]
        [return: MessageParameter(Name = "UsersList")]
        List<User_Key_Mapping> GetAllActiveUsers_Insights();

        [OperationContract(Name = "CreateCrowdTokenByUserName")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "CreateCrowdTokenByUserName?username={userName}")]
        [return: MessageParameter(Name = "CreateCrowdToken")]
        CrowdUserObj CreateCrowdTokenByUserName(string userName);

        [OperationContract(Name = "GetEmailAddressFromUserToken")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "GetEmailAddressFromUserToken?token={CrowdSSOToken}")]
        [return: MessageParameter(Name = "GetEmailAddressFromUserToken")]
        string GetEmailAddressFromUserToken(string CrowdSSOToken);


        [OperationContract(Name = "GetUserCrowdByEmail")]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "GetUserCrowdByEmail?email={Email}")]
        [return: MessageParameter(Name = "GetUserCrowdByEmail")]
        CrowdUserObj GetUserCrowdByEmail(string Email);


   

    }
}