using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;
using Afiniti.GRM.SecurityDTO;

using System.Configuration;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_REST")]
    public interface ISecurityService_REST
    {
        [OperationContract]
        [WebGet(ResponseFormat = WebMessageFormat.Json, UriTemplate = "AuthenticateUser/{UserName}/{Password}")]
        REST_UserObj AuthenticateUser(string UserName, string Password);

       
    }

}