using System.ServiceModel;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_PMO")]
    public interface ISecurityService_PMO
    {
        [OperationContract(Name = "AuthenticateUserPMO")]
        CrowdUserObj AuthenticateUser_PMO(string UserName, string Password); 
    }
}
