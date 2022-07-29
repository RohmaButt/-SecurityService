using System.ServiceModel;
using System.ServiceModel.Web;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_ETL")]
    public interface ISecurityService_ETL
    {
        [OperationContract]
        [WebGet(ResponseFormat = WebMessageFormat.Json, UriTemplate = "AuthenticateUser/{UserName}/{Password}")]
        REST_UserObj AuthenticateUser(string UserName, string Password);

    }
}