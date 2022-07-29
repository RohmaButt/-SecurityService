using Afiniti.GRM.SecurityDTO;
using System.ServiceModel;

namespace Afiniti.GRM.SecurityService
{
    [ServiceContract(Name = "SecurityService_CommercialGate")]
    public interface ISecurityService_CommercialGate
    {
        [OperationContract(Name = "GetUsersSecurityDataByToken_CG")]
        UserDTO GetUsersSecurityDataByToken_CG(string CrowdToken, string IPAddress);

        [OperationContract(Name = "AuthenticateAndAuthorizeByCrowd_CG")]
        UserDTO AuthenticateAndAuthorizeByCrowd_CG(string CrowdSSOToken, string IPAddress, string ControllerPath);

        [OperationContract(Name = "AuthenticateByCrowd_CG")]
        CrowdUserObj AuthenticateUserByCrowd_CG(string CrowdSSOToken);
    }
}