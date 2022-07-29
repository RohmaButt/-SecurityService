using System;
using System.Collections.Generic;
using System.ServiceModel;
using Afiniti.GRM.SecurityDTO;

namespace Afiniti.GRM.SecurityService
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the interface name "ISecurityService" in both code and config file together.
    [ServiceContract(Name ="SecurityService")]
    public interface ISecurityService
    {

        [OperationContract]
        SecurityDTO.UserDTO GetUsersSecurityData(string UserName, string IPAddress);

        [OperationContract]
        CrowdUserObj AuthenticateUserFromCrowd(string UserName, string Password);

        [OperationContract]
        CrowdUserObj AuthenticateUserFromCrowdByEmail(string Email);

        [OperationContract]
        int AuthenticateUserFromJira(string UserName, string Password);

        [OperationContract]
        void SendApprovalRequestEmail(string UserName, string Message);

        [OperationContract]
        long LogUserSessionStartActivity(string UserName, string IPAddress, string SessionID, string AuthenticationMetaData);

        [OperationContract]
        bool LogUserSessionEndActivity(long SessionId);

        [OperationContract]
        bool VerifyUserSession(string SessionId, string AccessURL);

        [OperationContract]
        User GetUserInstance(String UserName);

        [OperationContract]
        bool UpdateUserSecretInfo(String UserName, string newQuestion, string newAnswer);

        [OperationContract]
        bool ValidateUserSessionByCrowdToken(String CrowdToken);
        [OperationContract]
        bool ValidateUserSessionByEmail(String Email);
        [OperationContract]
        bool ValidateUserSessionByUsername(string UserName);

        [OperationContract]
        bool LogOutFromCrowd(String CrowdToken);

        [OperationContract]
        bool ExpireUserSession(string Email, string CrowdToken);

        [OperationContract]
        bool SaveSessionInDB(string Email, string CrowdToken);

        [OperationContract]
        CrowdUserObj GetUserObjectFromCrowdToken(string CrowdSSOToken);

        [OperationContract]
        bool CreateCrowdToken(string username, string password);

        [OperationContract]
        SecurityDTO.UserDTO GetUsersSecurityDataByToken(string CrowdToken, string IPAddress);

        [OperationContract]
        bool RemoveSSOTokenFromCrowd(string CrowdSSOToken);

        [OperationContract]
        User GetUserDataByEmail(string userEmail);

        [OperationContract]
        List<ContactAttribute> GetContactAttributes();

        [OperationContract]
        bool UpdateContactMapping(string mappedStr, Guid userRemoteKey);

        [OperationContract]
        List<User_Key_Mapping> GetUserKeyByUserName(List<string> lstUserNames);

        [OperationContract]
        List<User_Key_Mapping> GetUserNameByUserKey(List<Guid?> lstUserKeys);

        [OperationContract]
        bool IsUserAdmin(string UserName);

        [OperationContract]
        List<User_Key_Mapping> GetAllActiveUsers();

    }

}
