using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace Afiniti.GRM.SecurityDTO
{
    public class UserDTO
    {
        public string UserName { get; set; }
        public List<Permission> Permissions { get; set; }
        public Guid RoleKey { get; set; }
        public Guid UserKey { get; set; }
        public string RoleName { get; set; }
        public int ApprovalStatus { get; set; }

        public Guid UserRemoteKey { get; set; }
        public bool LoggedInFromNewIP { get; set; }
        public CrowdUserObj CrowdObj { get; set; }

        public string Email { get; set; }
        public string OutlookGenieAttrMapping { get; set; }
        public bool IsAdmin { get; set; }

        public UserObj userObj { get; set; }//For TimeKeeping only
        public bool CanImpersonate { get; set; }
    }
    public struct Permission
    {
        public Guid PermissionKey;
        public string Description;
        public string Key;
        public string Name;
        public string URL;
        public Guid TypeKey;
        public string CssClass;
        public string DisplayText;
        public int? SortOrder;
        public bool AdminLevel;
        public Guid? ParentKey;

    }

    public class CrowdUserObj
    {
        public string CrowdSSOToken { get; set; }
        public string Email { get; set; }
        public int AuthenticationCode { get; set; }
        public short ApprovalStatus { get; set; }
        public string UserName { get; set; }
        public string UserKey { get; set; }
        public string RemoteKey { get; set; }
        public string JSessionID { get; set; }
        public string AuthenticationMetaData { get; set; }
    }

    public class UserObj
    {
        public string DisplayName { get; set; }
        public string AvatarURL { get; set; }
    }

    public class CrowdUserObjMobile
    {
        public string CrowdSSOToken { get; set; }
        public string Email { get; set; }
        public int AuthenticationCode { get; set; }
        public short ApprovalStatus { get; set; }
        public string UserName { get; set; }
        public string DisplayName { get; set; }
        public string UserKey { get; set; }
        public string RemoteKey { get; set; }
        public string JSessionID { get; set; }
        public string AuthenticationMetaData { get; set; }
        public AppConfiguration AppConfiguration { get; set; }
        public string SpaceKey { get; set; }
    }

    public class REST_UserObj
    {
        public string Message { get; set; }
        public int StatusCode { get; set; }
        public string UserKey { get; set; }
    }

    public class AuthResponseModel
    {
        public HttpStatusCode HttpStatusCode { get; set; }
        public string Message { get; set; }
        public bool IsAuthenticated { get; set; }
        public string CrowdSSOToken { get; set; }
        public string UserDisplayName { get; set; }
        public string UserAvatarUrl { get; set; }
        public string JSessionID { get; set; }
    }

    public class AuthRequestModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
        public string IPAddress { get; set; }
        public string CrowdSSOToken { get; set; }
        public string ControllerPath { get; set; }
    }
    public class User_Key_Mapping
    {
        public string UserName { get; set; }
        public string UserKey { get; set; }
        public string Email { get; set; }

    }

    public class AppConfiguration
    {
        public string AppVersion { get; set; }
        public string DownloadUrl { get; set; }

    }
    public class ConfluenceUserObj
    {
        public string key { get; set; }
        public string name { get; set; }
        public string emailAddress { get; set; }
        public string displayName { get; set; }
        public bool active { get; set; }
    }
}
