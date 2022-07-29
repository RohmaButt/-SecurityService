using Afiniti.GRM.SecurityDTO;
using Afiniti.GRM.SecurityService.EmailService;
using Afiniti.GRM.Shared;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Net.Http;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Web.Configuration;

namespace Afiniti.GRM.SecurityService
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the class name "SecurityService" in code, svc and config file together.
    // NOTE: In order to launch WCF Test Client for testing this service, please select SecurityService.svc or SecurityService.svc.cs at the Solution Explorer and start debugging.
    public partial class SecurityService : ISecurityService, ISecurityService_ETL, ISecurityService_REST
    {
        public SecurityDTO.UserDTO GetUsersSecurityData(string UserName, string IPAddress)
        {
            // Exception ex = new Exception("I am in GetUsersSecurityData");
            // Utilities.LogException(ex, "");

            if (String.IsNullOrEmpty(UserName))
            {
                // Utilities.LogException(new Exception("Useranme is NULL or Empty"), "");
                return null;
            }
            /*
             UKB: Following Set of operations need to be performed here:
             1. Check if this user is already in GRMSecurity DB, if YES then get its Security Related Data and return
             2. If NO, insert this user in GRMSecurity DB and assign permissions as per "Normal User" Role Template and return that.
             */
            SecurityDTO.UserDTO data = null;
            try
            {
                string appKey = ConfigurationManager.AppSettings["GenieAppKey"].ToString();

                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {

                    bool IsFirstLogin = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower() && x.IsActive == true).Select(x => x).FirstOrDefault() == null;
                    if (IsFirstLogin)
                    {
                        //The user has Valid Confluence / Jira credentials but needs approval from Authorities to Use Genie

                        //Add data in Users Table

                        User newUser = new User();
                        newUser.UserName = UserName;
                        newUser.IsActive = true;
                        newUser.CanImpersonate = false;
                        newUser.UserKey = Guid.NewGuid();
                        newUser.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                        if (ConfigurationManager.AppSettings["DefaultQuestion"] != null)
                        {
                            newUser.SecQ = ConfigurationManager.AppSettings["DefaultQuestion"].ToString();
                        }
                        else
                        {
                            newUser.SecQ = "";
                        }
                        if (ConfigurationManager.AppSettings["DefaultAnswer"] != null)
                        {
                            newUser.SecA = ConfigurationManager.AppSettings["DefaultAnswer"].ToString();
                        }
                        else
                        {
                            newUser.SecA = "";
                        }
                        ctx.Users.AddObject(newUser);
                        ctx.SaveChanges();

                        Guid UserKey = newUser.UserKey;

                        //Add data in User_Roles_Rel Table
                        UserRole_Rel role_rel = new UserRole_Rel();
                        role_rel.UserKey = UserKey;
                        role_rel.RoleKey = RoleTypes.Normal.Value;
                        role_rel.UserRoleRelKey = Guid.NewGuid();
                        role_rel.IsActive = true;

                        ctx.UserRole_Rel.AddObject(role_rel);

                        ctx.SaveChanges();

                        var NormalUserPermissions = (from rolePermissions in ctx.RolePermission_Template
                                                     where rolePermissions.RoleKey == RoleTypes.Normal.Value && rolePermissions.IsActive == true
                                                     select rolePermissions).ToList();

                        List<UserPermission_Assignment> lstPermissions = new List<UserPermission_Assignment>();
                        foreach (var permission in NormalUserPermissions)
                        {
                            UserPermission_Assignment perm = new UserPermission_Assignment();
                            perm.UserKey = UserKey;
                            perm.PermissionKey = permission.PermissionKey;
                            perm.IsActive = true;
                            perm.UserPermissionAssignmentKey = Guid.NewGuid();
                            ctx.UserPermission_Assignment.AddObject(perm);
                            //lstPermissions.Add(perm);
                        }

                        ctx.SaveChanges();
                        SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                        record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                        record.UserName = UserName;
                        data = record;
                    }
                    else if (ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()).Select(x => x).FirstOrDefault().ApprovalStatus == (int)ApprovalStatus.Approved)
                    {

                        var query = (from user in ctx.Users
                                     join userRoles in ctx.UserRole_Rel on user.UserKey equals userRoles.UserKey
                                     join roles in ctx.Roles on userRoles.RoleKey equals roles.RoleKey
                                     where user.IsActive == true && roles.IsActive == true && userRoles.IsActive == true && user.UserName.ToLower() == UserName.ToLower()
                                     select new
                                     {
                                         UserName = user.UserName,
                                         RoleName = roles.Name,
                                         RoleKey = roles.RoleKey,
                                         UserKey = user.UserKey,
                                         ApprovalStatus = user.ApprovalStatus,
                                         UserRemoteKey = user.UserRemoteKey,
                                         Email = user.Email,
                                         IsAdmin = user.IsAdmin,
                                         MappingData = user.OutlookGenieAttrMapping,
                                         Permissions = (
                                                        from AppPermAssignment in ctx.ApplicationPermission_Assignment
                                                        join permissions in ctx.Permissions on AppPermAssignment.PermissionKey equals permissions.PermissionKey
                                                        join Apps in ctx.SecurityApps on AppPermAssignment.AppKey equals Apps.AppKey
                                                        where permissions.IsActive == true && AppPermAssignment.IsActive == true && Apps.AppName.ToLower() == appKey
                                                        select permissions).Intersect(
                                                            (
                                                        from permAssignment in ctx.UserPermission_Assignment
                                                        join permissions in ctx.Permissions on permAssignment.PermissionKey equals permissions.PermissionKey
                                                        where permAssignment.UserKey == user.UserKey && permissions.IsActive == true && permAssignment.IsActive == true
                                                        select permissions).ToList())
                                     }).FirstOrDefault();

                        SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                        record.RoleKey = query.RoleKey;
                        record.UserKey = query.UserKey;
                        record.RoleName = query.RoleName;
                        record.UserName = query.UserName;
                        record.ApprovalStatus = (int)query.ApprovalStatus;
                        record.UserRemoteKey = query.UserRemoteKey ?? Guid.Empty;
                        record.Email = query.Email;
                        record.OutlookGenieAttrMapping = query.MappingData;
                        record.IsAdmin = query.IsAdmin;

                        record.Permissions = new List<SecurityDTO.Permission>();
                        foreach (var permission in query.Permissions)
                        {
                            SecurityDTO.Permission _permission = new SecurityDTO.Permission();
                            _permission.PermissionKey = permission.PermissionKey; //[UKB] We dont need this as this data will be saved in Session and it will only increase the storage memory.
                            //_permission.Name = permission.Name;
                            // _permission.Description = permission.Description; //[UKB] We dont need this as this data will be saved in Session and it will only increase the storage memory.
                            _permission.TypeKey = permission.PermissionTypeKey;
                            _permission.Key = permission.Key;
                            _permission.URL = permission.URL;
                            _permission.CssClass = permission.CSSClass;
                            _permission.DisplayText = permission.DisplayText;
                            _permission.SortOrder = permission.SortOrder;
                            _permission.AdminLevel = false;
                            _permission.ParentKey = permission.ParentKey;//added for Menu Grouping Genie change
                            record.Permissions.Add(_permission);
                        }

                        // var userObj = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()).Select(x => x).FirstOrDefault();
                        //if(record.IsAdmin == true)
                        //{
                        var queryPermissions = (from permTemplate in ctx.RolePermission_Template
                                                join perm in ctx.Permissions on permTemplate.PermissionKey equals perm.PermissionKey
                                                where permTemplate.RoleKey == RoleTypes.Admin.Value && permTemplate.IsActive == true && perm.IsActive == true
                                                select perm).ToList();


                        //record.Permissions = new List<SecurityDTO.Permission>();
                        foreach (var permission in queryPermissions)
                        {
                            SecurityDTO.Permission _permission = new SecurityDTO.Permission();
                            _permission.PermissionKey = permission.PermissionKey; //[UKB] We dont need this as this data will be saved in Session and it will only increase the storage memory.
                                                                                  //_permission.Name = permission.Name;
                                                                                  // _permission.Description = permission.Description; //[UKB] We dont need this as this data will be saved in Session and it will only increase the storage memory.
                            _permission.TypeKey = permission.PermissionTypeKey;
                            _permission.Key = permission.Key;
                            _permission.URL = permission.URL;
                            _permission.CssClass = permission.CSSClass;
                            _permission.DisplayText = permission.DisplayText;
                            _permission.SortOrder = permission.SortOrder;
                            _permission.AdminLevel = true;

                            if (record.IsAdmin == true)
                            {
                                record.Permissions.Add(_permission);
                            }
                            else if (record.Permissions.Any(x => x.PermissionKey == _permission.PermissionKey))
                            {
                                Utilities.WriteTrace("Removing Permission with Name : " + permission.Name);
                                record.Permissions.RemoveAll(x => x.PermissionKey == _permission.PermissionKey);
                            }
                        }
                        //  }

                        data = record;

                        data.LoggedInFromNewIP = !ctx.UserSessions.Where(x => x.IPAddress == IPAddress).Any();

                        //  SendLoginEmail(UserName);
                    }

                    else
                    {
                        SecurityDTO.UserDTO record = new SecurityDTO.UserDTO();
                        record.UserName = UserName;
                        record.ApprovalStatus = (int)ApprovalStatus.PendingForApproval;
                        data = record;
                    }
                }
            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "");
            }
            return data;
        }

        public CrowdUserObj AuthenticateUserFromCrowd(string pUserName, string pPassword)
        {
            CrowdUserObj obj = null;
            // obj.AuthenticationCode = 0; //Unauthenticated
            // Utilities.LogException(new Exception("In AuthenticateUser"), "");
            obj = AuthenticateUserFromCrowd_internal(pUserName, pPassword);

            return obj;
        }
        public CrowdUserObj AuthenticateUserFromCrowdByEmail(string Email)
        {

            CrowdUserObj obj = null;
            if (String.IsNullOrEmpty(Email))
            {
                return obj;
            }

            string userName = String.Empty;
            using (GRM_Security_Entities ctx = new GRM_Security_Entities())
            {
                var query = ctx.Users.Where(x => x.Email != null).Where(y => y.Email.ToLower() == Email.ToLower()).FirstOrDefault();
                if (query != null)
                {
                    userName = query.UserName;
                }
            }
            obj = AuthenticateUserFromCrowd_internal(userName, "", true);

            return obj;
        }

        public CrowdUserObj AuthenticateUserFromCrowdByUserName(string userName)
        {

            CrowdUserObj obj = null;
            if (String.IsNullOrEmpty(userName))
            {
                return obj;
            }

            obj = AuthenticateUserFromCrowd_internal(userName, "", true);

            return obj;
        }

        public int AuthenticateUserFromJira(string pUserName, string pPassword)
        {

            int AuthenticationCode = 0; //Unauthenticated
                                        // Utilities.LogException(new Exception("In AuthenticateUser"), "");

            AuthenticationCode = AuthenticateUserFromJira_internal(pUserName, pPassword);

            return AuthenticationCode;
        }

        private int AuthenticateUserFromJira_internal(string pUserName, string pPassword)
        {
            int result = 0;
            string strURI = WebConfigurationManager.AppSettings["JiraBaseURL"];
            string strJiraProjectsURL = WebConfigurationManager.AppSettings["JiraProjectsURL"];
            using (System.Net.Http.HttpClient client = new System.Net.Http.HttpClient())
            {
                try
                {
                    client.BaseAddress = new System.Uri(strURI);
                    byte[] cred = UTF8Encoding.UTF8.GetBytes(pUserName + ":" + pPassword);

                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(cred));
                    client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                    HttpResponseMessage messge = Task.Run(() => client.GetAsync(strJiraProjectsURL)).Result;
                    if (messge.IsSuccessStatusCode)
                    {
                        //response = "Authenticated";
                        result = 1; //Authenticated
                        //Utilities.LogException(new Exception("Authentication from JIRA successful"), "");
                    }
                    else
                    {
                        //response = "Authentication Failed";
                        result = 2; //Authentication Failed
                                    // Utilities.LogException(new Exception("Authentication from JIRA failed"), "");

                        if (messge.Headers != null && messge.Headers.Count() > 0)
                        {
                            IEnumerable<string> headerInfo;
                            var authenticationFailReason = messge.Headers.TryGetValues("X-Authentication-Denied-Reason", out headerInfo);
                            if (authenticationFailReason)
                            {
                                var _reason = headerInfo.FirstOrDefault();
                                if (_reason != null && _reason.Contains("CAPTCHA_CHALLENGE"))
                                {
                                    //response = "CAPTCHA REQUIRED";
                                    result = 3; //CAPTCHA REQUIRED
                                    //Utilities.LogException(new Exception("Authentication from JIRA failed, Captcha appearing"), "");
                                }
                            }

                        }
                        else
                        {
                            //response = "Authentication Failed";
                            result = 2; //Authentication Failed
                                        // Utilities.LogException(new Exception("Authentication from JIRA failed"), "");
                        }

                    }

                }
                catch (Exception ex)
                {
                    result = 2; //Authentication Failed
                    Utilities.LogException(ex, "");
                }
            }

            return result;
        }
        private int AuthenticateUserFromConfluence(string pUserName, string pPassword)
        {
            int result = 0;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ConfigurationManager.AppSettings["ConfluenceBaseUrl"] + "/rest/api/space");
            request.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(pUserName + ":" + pPassword)));
            request.Method = "GET";
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                result = 1; //Authenticated
            }
            catch (Exception ex)
            {
                result = 0; //Unauthenticated
                Utilities.LogException(ex, "");
            }
            return result;
        }

        //internal static async void SendLoginEmail(string UserName)
        //{
        //    string toEmail = ConfigurationManager.AppSettings["ApprovalEmail"].ToString();
        //    List<string> msg = new List<string>() { UserName + " logged in" };

        //    await Task.Factory.StartNew(() => SuggestionEmail(toEmail, msg));
        //}
        internal static async void SendRequestEmail(string UserName, string Message, string ToEmailKey = "", string EmailTemplateName = "")
        {
            string toEmail = ConfigurationManager.AppSettings["ApprovalEmail"].ToString();
            if (!String.IsNullOrEmpty(ToEmailKey))
            {
                toEmail = ConfigurationManager.AppSettings[ToEmailKey].ToString();
            }
            List<string> msg = new List<string>() { UserName, Message };

            await Task.Factory.StartNew(() => SendApprovalEmail(toEmail, msg, EmailTemplateName));
        }

        private static void SendApprovalEmail(string pEmail, List<string> pMessage, string pEmailTemplateName)
        {
            try
            {
                using (EmailServiceClient context = new EmailServiceClient())
                {
                    string templateName = ConfigurationManager.AppSettings["ApprovalEmailTemplateName"].ToString();
                    if (!String.IsNullOrEmpty(pEmailTemplateName))
                    {
                        templateName = ConfigurationManager.AppSettings[pEmailTemplateName].ToString();
                    }

                    context.SendEmail(pEmail, pMessage, templateName);
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }

        }

        public void SendApprovalRequestEmail(string UserName, string Message)
        {
            SendRequestEmail(UserName, Message);
        }
        public void SendApprovalRequestEmail_DmsMac(string UserName, string Message)
        {
            SendRequestEmail(UserName, Message, "DmsMacApprovalEmail", "DmsMacApprovalTemplateName");
        }


        private void MarkPreviousSessionsAsExpired(GRM_Security_Entities ctx, string UserName, string IPAddress, string SessionID)
        {

            var ExistingSessions = ctx.UserSessions.Where(x => x.ASPNETSessionID == SessionID && x.Expired == false && x.IPAddress == IPAddress);
            if (ExistingSessions.Any()) // Mark Existing Session(s) as expired
            {
                //Utilities.LogException(new Exception("Going to remove Existing Sessions for " + UserName), "");
                foreach (UserSession sess in ExistingSessions.ToList())
                {
                    sess.Expired = true;
                    sess.EndDate = DateTime.Now;
                    //ctx.UserSessions.Attach(sess);
                }
                ctx.SaveChanges();
            }

        }
        public long LogUserSessionStartActivity(string UserName, string IPAddress, string SessionID, string AuthenticationMetaData)
        {
            long SessionId = -1;
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    MarkPreviousSessionsAsExpired(ctx, UserName, IPAddress, SessionID);
                    Guid UserKey = ctx.Users.Where(x => x.UserName == UserName).Select(x => x.UserKey).FirstOrDefault();
                    //Utilities.LogException(new Exception("UserKey is  " + UserKey), "");
                    //Now add the new session
                    UserSession newSession = new UserSession()
                    {
                        StartDate = DateTime.Now,
                        EndDate = null,
                        Expired = false,
                        IPAddress = IPAddress,
                        IsActive = true,
                        SessionStatus = 1,
                        ASPNETSessionID = SessionID,
                        UserKey = UserKey,
                        CrowdToken = EncryptionClass.Encrypt_Decrypt(AuthenticationMetaData, true)
                    };
                    ctx.UserSessions.AddObject(newSession);
                    ctx.SaveChanges();
                    SessionId = newSession.SessionId;
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                SessionId = -1;
            }
            return SessionId;
        }
        public bool LogUserSessionEndActivity(long SessionId)
        {
            bool status = false;
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {

                    var ExistingSession = ctx.UserSessions.Where(x => x.SessionId == SessionId && x.Expired == false).FirstOrDefault();
                    if (ExistingSession != null) // Mark Existing Session as expired
                    {
                        // Utilities.LogException(new Exception("Going to remove Existing Sessions for UserKey: "+ ExistingSession.UserKey + " SessionID" + SessionId), "");

                        ExistingSession.Expired = true;
                        ExistingSession.EndDate = DateTime.Now;
                        ctx.SaveChanges();
                        status = true;
                    }
                    else
                    {
                        //Utilities.LogException(new Exception("No Existing Session found for SessionId " + SessionId), "");
                        status = false;
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                status = false;
            }
            return status;
        }
        internal void LogUserActivity(int sessionId, string URL)
        {
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    UserSession_Logs log = new UserSession_Logs()
                    {
                        AccessURL = URL,
                        DateTime = DateTime.Now,
                        SessionId = sessionId
                    };
                    ctx.UserSession_Logs.AddObject(log);
                    ctx.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }

        }

        //internal void MarkSessionAsSuspicious(int sessionId)
        //{
        //    try
        //    {
        //        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
        //        {
        //            UserSession_Logs log = new UserSession_Logs()
        //            {
        //                AccessURL = URL,
        //                DateTime = DateTime.Now,
        //                SessionId = sessionId
        //            };
        //            ctx.UserSession_Logs.AddObject(log);
        //            ctx.SaveChanges();
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Utilities.LogException(ex, "");
        //    }

        //}
        public bool VerifyUserSession(string SessionId, string AccessURL)
        {
            bool status = false;
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    //var userKey = ctx.Users.Where(x => x.UserRemoteKey == UserRemoteKey).Select(y => y.UserKey).FirstOrDefault();
                    int sessionId = Convert.ToInt32(SessionId);
                    var query = ctx.UserSessions.Where(x => x.SessionId == sessionId && x.Expired == false && x.IsActive == true).FirstOrDefault();
                    if (query != null) //Session is active for this User, so all is well
                    {
                        status = true;
                        Task.Factory.StartNew(() => LogUserActivity(sessionId, AccessURL));
                    }
                    else
                    {
                        //Unauthenticated_Requests unauthReq = new Unauthenticated_Requests()
                        //{
                        //    AccessTime = DateTime.Now,
                        //    IsActive = true,
                        //    UserKey = userKey,
                        //    RequestedURL = AccessURL
                        //};
                        //ctx.Unauthenticated_Requests.AddObject(unauthReq);
                        //ctx.SaveChanges();
                        query.MarkedAsSuspicious = true;
                        ctx.SaveChanges();
                        status = false;
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                status = false;
            }

            return status;
        }

        //public User GetUserInstance(Guid UserRemoteKey)
        //{
        //    User userObj = null;
        //    try
        //    {
        //        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
        //        {
        //            userObj = ctx.Users.Where(y => y.UserRemoteKey == UserRemoteKey && y.ApprovalStatus == 2 && y.IsActive == true).Select(x => x).FirstOrDefault();
        //            if(!String.IsNullOrEmpty (userObj.SecA))
        //            {
        //                string decryptedAns = "";
        //                try
        //                {
        //                    decryptedAns = EncryptionClass.Encrypt_Decrypt(userObj.SecA, false);

        //                }
        //                catch(Exception ex)
        //                {
        //                    Utilities.LogException(ex, "");
        //                }
        //                userObj.SecA = decryptedAns;
        //            }
        //        }
        //    }
        //    catch(Exception ex)
        //    {
        //        Utilities.LogException(ex, "");
        //    }

        //    return userObj;
        //}

        public User GetUserInstance(String UserName)
        {
            User userObj = null;
            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    userObj = ctx.Users.Where(y => y.UserName == UserName && y.ApprovalStatus == 2 && y.IsActive == true).Select(x => x).FirstOrDefault();
                    if (!String.IsNullOrEmpty(userObj.SecA))
                    {
                        string decryptedAns = "";
                        try
                        {
                            decryptedAns = EncryptionClass.Encrypt_Decrypt(userObj.SecA, false);

                        }
                        catch (Exception ex)
                        {
                            Utilities.LogException(ex, "");
                        }
                        userObj.SecA = decryptedAns;
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }

            return userObj;
        }


        //public bool UpdateUserSecretInfo(Guid UserRemoteKey, string newQuestion,string newAnswer)
        //{
        //    bool status = false;

        //    try
        //    {
        //        using (GRM_Security_Entities ctx = new GRM_Security_Entities())
        //        {
        //            var userObj = ctx.Users.Where(y => y.UserRemoteKey == UserRemoteKey && y.ApprovalStatus == 2 && y.IsActive == true).Select(x => x).FirstOrDefault();
        //            if(userObj != null)
        //            {
        //                if (!String.IsNullOrEmpty(newQuestion))
        //                    userObj.SecQ = newQuestion;

        //                if (!String.IsNullOrEmpty(newAnswer))
        //                {
        //                   // userObj.SecA = newAnswer;
        //                    userObj.SecA = EncryptionClass.Encrypt_Decrypt(newAnswer, true);
        //                }

        //                ctx.SaveChanges();
        //                status = true;
        //            }
        //        }
        //    }
        //    catch(Exception ex)
        //    {
        //        status = false;
        //        Utilities.LogException(ex, "");
        //    }
        //    return status;
        //}
        public bool UpdateUserSecretInfo(String UserName, string newQuestion, string newAnswer)
        {
            bool status = false;

            try
            {
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    var userObj = ctx.Users.Where(y => y.UserName == UserName && y.ApprovalStatus == 2 && y.IsActive == true).Select(x => x).FirstOrDefault();
                    if (userObj != null)
                    {
                        if (!String.IsNullOrEmpty(newQuestion))
                        {
                            userObj.SecQ = newQuestion;
                        }

                        if (!String.IsNullOrEmpty(newAnswer))
                        {
                            // userObj.SecA = newAnswer;
                            userObj.SecA = EncryptionClass.Encrypt_Decrypt(newAnswer, true);
                        }

                        ctx.SaveChanges();
                        status = true;
                    }
                }
            }
            catch (Exception ex)
            {
                status = false;
                Utilities.LogException(ex, "");
            }
            return status;
        }

        public bool ValidateUserSessionByCrowdToken(string CrowdToken)
        {
            bool isvalidated = false;
            using (GRM_Security_Entities ctx = new GRM_Security_Entities())
            {
                isvalidated = ctx.UserSessions.Where(x => x.CrowdToken == CrowdToken && x.IsActive == true).Any();
            }
            return isvalidated;
        }

        public bool ValidateUserSessionByEmail(string Email)
        {
            bool isvalidated = false;
            using (GRM_Security_Entities ctx = new GRM_Security_Entities())
            {
                var userObj = ctx.Users.Where(x => x.Email == Email).FirstOrDefault();
                if (userObj != null)
                {
                    isvalidated = ctx.UserSessions.Where(x => x.UserKey == userObj.UserKey && x.Expired == false).Any();
                }

            }
            return isvalidated;
        }
        public bool ValidateUserSessionByUsername(string UserName)
        {
            bool isvalidated = false;
            using (GRM_Security_Entities ctx = new GRM_Security_Entities())
            {

                var userObj = ctx.Users.Where(x => x.UserName == UserName).FirstOrDefault();
                if (userObj != null)
                {
                    isvalidated = ctx.UserSessions.Where(x => x.UserKey == userObj.UserKey && x.Expired == false).Any();
                }

            }
            return isvalidated;
        }

        public bool LogOutFromCrowd(string CrowdToken)
        {
            bool expired = false;
            using (GRM_Security_Entities ctx = new GRM_Security_Entities())
            {
                if (!String.IsNullOrEmpty(CrowdToken))
                {
                    var query = ctx.UserSessions.Where(x => x.CrowdToken == CrowdToken).FirstOrDefault();
                    if (query != null)
                    {
                        query.Expired = false;
                        ctx.SaveChanges();
                        expired = true;
                    }
                }
            }
            return expired;
        }

        public REST_UserObj AuthenticateUser(string UserName, string Password)
        {
            try
            {
                // Utilities.LogException(new Exception("In AuthenticateUser from REST CALL"), "");
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                    ConfigurationManager.AppSettings["CrowdAppName"],
                    ConfigurationManager.AppSettings["CrowdAppPass"]);

                if (String.IsNullOrEmpty(UserName) || String.IsNullOrEmpty(Password))
                {
                    //Utilities.LogException(new Exception("Invalid Parameters"), "");
                    return SendErrorResponse();
                }

                Password = System.Uri.UnescapeDataString(Password);
                REST_UserObj UserObj = null;
                var res = crowdService.Authenticate(UserName, Password);
                if (res)
                {
                    UserObj = new REST_UserObj();
                    UserObj.Message = "Success";
                    UserObj.StatusCode = (int)HttpStatusCode.OK;
                    using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                    {
                        //UserObj.UserKey = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                        //                                    && x.IsActive == true
                        //                                    && x.ApprovalStatus == (int)ApprovalStatus.Approved)
                        //                                    .Select(y => y.UserRemoteKey).FirstOrDefault().ToString();

                        IQueryable<User> users = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                                                                      && x.IsActive == true);
                        Expression<Func<User, bool>> approvalCriteria = Utilities.CreateApprovalCriteria(GetApprovalPropertyNameByEndPoint());
                        if (approvalCriteria == null)
                        {

                        }
                        users = users.Where(approvalCriteria);

                        UserObj.UserKey = users.FirstOrDefault()?.UserRemoteKey.ToString();
                    }


                }
                else
                {
                    return SendErrorResponse("Please check your credentials", HttpStatusCode.Unauthorized);
                }
                return UserObj;
            }
            catch (Exception ex)
            {
                Guid errorCode = Guid.NewGuid();
                Utilities.LogException(new Exception("Error Code:" + errorCode), "");
                Utilities.LogException(ex, "");
                return SendErrorResponse("ErrorCode: [" + errorCode + "]. Something went wrong.");
            }
        }
        public CrowdUserObj GetUserRemoteKeyByEmailOnly(string Email)
        {
            CrowdUserObj crowdUserObj = new CrowdUserObj()
            {
                AuthenticationCode = 2
            };
            try
            {
                if (String.IsNullOrEmpty(Email))
                {
                    return crowdUserObj;
                }
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    Exception exc;
                    var user = ctx.Users.Where(x => x.Email != null).FirstOrDefault(y => y.Email.ToLower() == Email.ToLower());
                    if (user != null)
                    {
                        crowdUserObj.RemoteKey = user.UserRemoteKey?.ToString();
                        crowdUserObj.UserKey = user.UserKey.ToString();
                        crowdUserObj.ApprovalStatus = user.GenieMobileApproval;
                        crowdUserObj.UserName = user.UserName;
                        crowdUserObj.Email = user.Email;
                        if (user.UserRemoteKey == null)
                        {
                            exc = new Exception("UserRemoteKey is null against the email: " + Email);
                            Utilities.WriteTrace("UserRemoteKey is null against the email: " + Email);
                        }
                    }
                    else
                    {
                        exc = new Exception("User could not be found with email: " + Email);
                        Utilities.WriteTrace("User could not be found with email: " + Email);
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }

            return crowdUserObj;
        }
        public CrowdUserObj AuthenticateUserFromCrowdForGenieMobile(string UserName, string Password, bool OverridePassword = false)
        {
            var exc = new Exception("in: AuthenticateUserFromCrowdForGenieMobile");
            //Utilities.LogException(exc, "");

            Afiniti.GRM.SecurityDTO.CrowdUserObj crowdUserObj = new CrowdUserObj()
            {
                AuthenticationCode = 2,
                ApprovalStatus = 1
            };
            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                    ConfigurationManager.AppSettings["CrowdAppName"],
                    ConfigurationManager.AppSettings["CrowdAppPass"]);
                //var res = crowdService.Authenticate(UserName, Password);
                var res = crowdService.CreateCrowdToken_internal(UserName, Password, OverridePassword);
                if (res)
                {
                    crowdUserObj.AuthenticationCode = 1;
                    exc = new Exception(UserName + " Authenticated from crowd");
                    //Utilities.LogException(exc, "");

                    using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                    {
                        IQueryable<User> users = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                                                                      && x.IsActive == true);
                        Expression<Func<User, bool>> approvalCriteria =
                            Utilities.CreateApprovalCriteria(GetApprovalPropertyNameByEndPoint());

                        users = users.Where(approvalCriteria);
                        var user = users.FirstOrDefault();
                        if (user != null)
                        {
                            exc = new Exception(UserName + " has been Authenticated from Security Service");
                            //Utilities.LogException(exc, "");
                            crowdUserObj.RemoteKey = user.UserRemoteKey.ToString();
                            crowdUserObj.UserKey = user.UserKey.ToString();
                            crowdUserObj.ApprovalStatus = user.GenieMobileApproval;
                            crowdUserObj.UserName = user.UserName;
                            crowdUserObj.Email = user.Email;

                            crowdUserObj.CrowdSSOToken = crowdService.CROWD_TOKEN;
                            crowdUserObj.JSessionID = crowdService.CROWD_JSESSIONID;
                            crowdUserObj.AuthenticationMetaData =
                                EncryptionClass.Encrypt_Decrypt(
                                    ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" +
                                    crowdService.CROWD_JSESSIONID + ";" +
                                    ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" +
                                    crowdService.CROWD_TOKEN, true);
                        }
                        else
                        {
                            exc = new Exception(UserName + " Could not be Authenticated from Security Service");
                            //Utilities.LogException(exc, "");
                        }
                    }

                }
                else
                {
                    exc = new Exception(UserName + " Could not be Authenticated from CROWD");
                    //Utilities.LogException(exc, "");
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }

            return crowdUserObj;
        }
        public CrowdUserObj AuthenticateUserFromCrowdForJiraMobile(string UserName, string Password)
        {
            var exc = new Exception("in: AuthenticateUserFromCrowdForJiraMobile");
            //Utilities.LogException(exc, "");

            Afiniti.GRM.SecurityDTO.CrowdUserObj crowdUserObj = new CrowdUserObj()
            {
                AuthenticationCode = 2,
                ApprovalStatus = 1
            };
            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                    ConfigurationManager.AppSettings["CrowdAppName"],
                    ConfigurationManager.AppSettings["CrowdAppPass"]);
                //var res = crowdService.Authenticate(UserName, Password);
                var res = crowdService.CreateCrowdToken_internal(UserName, Password);
                if (res)
                {
                    crowdUserObj.AuthenticationCode = 1;
                    exc = new Exception("Authenticated from crowd");
                    //Utilities.LogException(exc, "");



                    exc = new Exception("Authenticated from crowd");
                    //Utilities.LogException(exc, "");

                    using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                    {
                        //UserObj.UserKey = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                        //                                    && x.IsActive == true
                        //                                    && x.ApprovalStatus == (int)ApprovalStatus.Approved)
                        //                                    .Select(y => y.UserRemoteKey).FirstOrDefault().ToString();

                        IQueryable<User> users = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                                                                      && x.IsActive == true);
                        Expression<Func<User, bool>> approvalCriteria = Utilities.CreateApprovalCriteria(GetApprovalPropertyNameByEndPoint());
                        exc = new Exception("Approval Criteria: " + approvalCriteria);
                        //Utilities.LogException(exc, "");
                        users = users.Where(approvalCriteria);
                        var user = users.FirstOrDefault();
                        if (user != null)
                        {
                            crowdUserObj.RemoteKey = user.UserRemoteKey.ToString();
                            crowdUserObj.UserKey = user.UserKey.ToString();
                            crowdUserObj.ApprovalStatus = user.JiraMobileApproval;
                            crowdUserObj.UserName = user.UserName;
                            crowdUserObj.Email = user.Email;

                            crowdUserObj.CrowdSSOToken = crowdService.CROWD_TOKEN;
                            crowdUserObj.JSessionID = crowdService.CROWD_JSESSIONID;
                            crowdUserObj.AuthenticationMetaData = EncryptionClass.Encrypt_Decrypt(ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" + crowdService.CROWD_JSESSIONID + ";" + ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" + crowdService.CROWD_TOKEN, true);
                        }
                    }



                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }
            exc = new Exception("Could not Authenticate from crowd");
            //Utilities.LogException(exc, "");
            return crowdUserObj;
        }
        public CrowdUserObj AuthenticateUserFromCrowdForPMO(string UserName, string Password)
        {
            var exc = new Exception("in: AuthenticateUserFromCrowdForPMO");
            //Utilities.LogException(exc, "");

            Afiniti.GRM.SecurityDTO.CrowdUserObj crowdUserObj = new CrowdUserObj()
            {
                AuthenticationCode = 2,
                ApprovalStatus = 1
            };
            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                    ConfigurationManager.AppSettings["CrowdAppName"],
                    ConfigurationManager.AppSettings["CrowdAppPass"]);
                //var res = crowdService.Authenticate(UserName, Password);
                var res = crowdService.CreateCrowdToken_internal(UserName, Password);
                if (res)
                {
                    crowdUserObj.AuthenticationCode = 1;
                    exc = new Exception("Authenticated from crowd");
                    //Utilities.LogException(exc, "");



                    exc = new Exception("Authenticated from crowd");
                    //Utilities.LogException(exc, "");

                    using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                    {
                        //UserObj.UserKey = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                        //                                    && x.IsActive == true
                        //                                    && x.ApprovalStatus == (int)ApprovalStatus.Approved)
                        //                                    .Select(y => y.UserRemoteKey).FirstOrDefault().ToString();

                        IQueryable<User> users = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                                                                      && x.IsActive == true);
                        Expression<Func<User, bool>> approvalCriteria = Utilities.CreateApprovalCriteria(GetApprovalPropertyNameByEndPoint());
                        exc = new Exception("Approval Criteria: " + approvalCriteria);
                        //Utilities.LogException(exc, "");
                        users = users.Where(approvalCriteria);
                        var user = users.FirstOrDefault();
                        if (user != null)
                        {
                            crowdUserObj.RemoteKey = user.UserRemoteKey.ToString();
                            crowdUserObj.UserKey = user.UserKey.ToString();
                            crowdUserObj.ApprovalStatus = user.JiraMobileApproval;
                            crowdUserObj.UserName = user.UserName;
                            crowdUserObj.Email = user.Email;

                            crowdUserObj.CrowdSSOToken = crowdService.CROWD_TOKEN;
                            crowdUserObj.JSessionID = crowdService.CROWD_JSESSIONID;
                            crowdUserObj.AuthenticationMetaData = EncryptionClass.Encrypt_Decrypt(ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" + crowdService.CROWD_JSESSIONID + ";" + ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" + crowdService.CROWD_TOKEN, true);
                        }
                    }



                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }
            exc = new Exception("Could not Authenticate from crowd");
            //Utilities.LogException(exc, "");
            return crowdUserObj;
        }
        public CrowdUserObj AuthenticateUserFromCrowd_internal(string UserName, string Password, bool OverridePassword = false)
        {
            CrowdUserObj crowdUserObj = new CrowdUserObj();
            try
            {
                crowdUserObj.AuthenticationCode = 2; //Unauthenticated

                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                                                                                         ConfigurationManager.AppSettings["CrowdAppName"],
                                                                                         ConfigurationManager.AppSettings["CrowdAppPass"]);
                //var res = crowdService.Authenticate(UserName, Password);
                var res = crowdService.CreateCrowdToken_internal(UserName, Password, OverridePassword);


                if (res)
                {

                    crowdUserObj.AuthenticationCode = 1;
                    crowdUserObj.CrowdSSOToken = crowdService.CROWD_TOKEN;
                    crowdUserObj.JSessionID = crowdService.CROWD_JSESSIONID;
                    crowdUserObj.AuthenticationMetaData = EncryptionClass.Encrypt_Decrypt(ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" + crowdService.CROWD_JSESSIONID + ";" + ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" + crowdService.CROWD_TOKEN, true);
                    crowdUserObj.UserName = UserName;
                    // crowdUserObj.Email = crowdService.Email;
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }

            Exception exc3 = new Exception("Authenticating User from username only: " + crowdUserObj.CrowdSSOToken + " : " + crowdUserObj.JSessionID);
            //Utilities.LogException(exc3, "");

            return crowdUserObj;
        }


        public bool ExpireUserSession(string Email, string CrowdToken)
        {
            throw new NotImplementedException();
        }

        public bool SaveSessionInDB(string Email, string CrowdToken)
        {
            throw new NotImplementedException();
        }

        public CrowdUserObj GetUserObjectFromCrowdToken(string CrowdSSOToken)
        {
            CrowdUserObj obj = null;
            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppName"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppPass"]);
                obj = crowdService.GetUserObjectByToken(CrowdSSOToken);
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return obj;
        }

        public bool CreateCrowdToken(string username, string password)
        {
            bool res = false;
            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppName"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppPass"]);
                return crowdService.CreateCrowdToken_internal(username, password);
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                return res;
            }
        }

        public SecurityDTO.UserDTO GetUsersSecurityDataByToken(string CrowdToken, string IPAddress)
        {
            UserDTO Obj = null;

            try
            {
                var crowdObj = GetUserObjectFromCrowdToken(CrowdToken);
                if (crowdObj != null)
                {
                    Obj = GetUsersSecurityData(crowdObj.UserName, IPAddress);
                    Obj.CrowdObj = new CrowdUserObj();
                    Obj.CrowdObj.CrowdSSOToken = CrowdToken;
                    Obj.CrowdObj.JSessionID = crowdObj.JSessionID;
                    Obj.CrowdObj.AuthenticationMetaData = EncryptionClass.Encrypt_Decrypt(ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" + crowdObj.JSessionID + ";" + ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" + CrowdToken, true);
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return Obj;

        }

        public bool RemoveSSOTokenFromCrowd(string CrowdSSOToken)
        {
            bool blnRemoved = false;

            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppName"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppPass"]);
                blnRemoved = crowdService.DeleteSession(CrowdSSOToken);
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return blnRemoved;
        }

        public User GetUserDataByEmail(string userEmail)
        {
            try
            {
                if (string.IsNullOrEmpty(userEmail))
                {
                    return null;
                }
                using (var context = new GRM_Security_Entities())
                {
                    var user = context.Users.FirstOrDefault(
                         obj => (!string.IsNullOrEmpty(obj.Email) && obj.Email.ToLower().Equals(userEmail.ToLower())));
                    return user;
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return null;
        }

        public List<ContactAttribute> GetContactAttributes()
        {
            using (var context = new GRM_Security_Entities())
            {
                return context.ContactAttributes.ToList();
            }
        }

        public bool UpdateContactMapping(string mappedStr, Guid userRemoteKey)
        {
            using (var context = new GRM_Security_Entities())
            {
                var userObj = context.Users.FirstOrDefault(user => user.UserRemoteKey == userRemoteKey);
                if (userObj != null && !string.IsNullOrEmpty(mappedStr))
                {
                    userObj.OutlookGenieAttrMapping = mappedStr;
                    context.SaveChanges();
                    return true;
                }
                return false;
            }
        }

        private REST_UserObj SendErrorResponse(string message = "", HttpStatusCode code = HttpStatusCode.BadRequest)
        {
            return new REST_UserObj
            {
                StatusCode = (int)code,
                Message = String.IsNullOrEmpty(message) ? "Invalid parameters" : message,
                UserKey = Guid.Empty.ToString()
            };
        }

        public static string GetApprovalPropertyNameByEndPoint()
        {
            string propertyName;
            string strContractName = OperationContext.Current.EndpointDispatcher.ContractName;

            switch (strContractName)
            {
                case "SecurityService":
                    propertyName = "ApprovalStatus";
                    break;
                case "SecurityService_ETL":
                    propertyName = "ETLApprovalStatus";
                    break;
                case "SecurityService_GenieMobile":
                    propertyName = "GenieMobileApproval";
                    break;
                case "SecurityService_JiraMobile":
                    propertyName = "JiraMobileApproval";
                    break;
                case "SecurityService_PMO":
                    propertyName = "PMOApproval";
                    break;
                case "SecurityService_DMS":
                    propertyName = "DMSMACApproval";
                    break;
                default:
                    propertyName = "ApprovalStatus";
                    break;
            }
            return propertyName;
        }

        public List<User_Key_Mapping> GetUserKeyByUserName(List<string> lstUserNames)
        {
            try
            {
                if (lstUserNames == null || !lstUserNames.Any())
                {
                    return null;
                }
                List<User_Key_Mapping> lstMappingData = new List<User_Key_Mapping>();
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {

                    var query = from user in ctx.Users
                                where user.IsActive && lstUserNames.Contains(user.UserName)
                                select new
                                {
                                    UserName = user.UserName,
                                    UserRemoteKey = user.UserRemoteKey
                                };
                    if (query.Any())
                    {
                        foreach (var item in lstUserNames)
                        {
                            User_Key_Mapping obj = new User_Key_Mapping
                            {
                                UserName = item,
                                UserKey = query.Any(x => x.UserName == item) ? query.FirstOrDefault(x => x.UserName == item)?
                                                                                    .UserRemoteKey.ToString() : string.Empty
                            };
                            lstMappingData.Add(obj);
                        }
                    }
                }
                return lstMappingData;
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                return null;
            }
        }

        public List<User_Key_Mapping> GetUserNameByUserKey(List<Guid?> lstUserKeys)
        {
            try
            {
                if (lstUserKeys == null || !lstUserKeys.Any())
                {
                    return null;
                }
                List<User_Key_Mapping> lstMappingData = null;
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {

                    var query = from user in ctx.Users
                                where user.IsActive && lstUserKeys.Contains(user.UserRemoteKey)
                                select new
                                {
                                    UserName = user.UserName,
                                    UserRemoteKey = user.UserRemoteKey,
                                    Email = user.Email
                                };
                    if (query.Any())
                    {
                        lstMappingData = new List<User_Key_Mapping>();
                        foreach (var item in lstUserKeys)
                        {
                            User_Key_Mapping obj = new User_Key_Mapping
                            {
                                UserKey = item?.ToString(),
                                UserName = query.Any(x => x.UserRemoteKey == item) ? query.FirstOrDefault(x => x.UserRemoteKey == item)?
                                                                                    .UserName : string.Empty,
                                Email = query.Any(x => x.UserRemoteKey == item) ? query.FirstOrDefault(x => x.UserRemoteKey == item)?
                                                                                    .Email : string.Empty,
                            };
                            lstMappingData.Add(obj);
                        }
                    }
                }
                return lstMappingData;
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                return null;
            }
        }
        public bool IsUserAdmin(string UserName)
        {
            bool isAdmin = false;

            if (String.IsNullOrEmpty(UserName))
            {
                return isAdmin;
            }

            try
            {
                using (var ctx = new GRM_Security_Entities())
                {
                    isAdmin = ctx.Users.Any(x => x.UserName.ToLower() == UserName.ToLower() && x.IsAdmin == true);
                }

            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }

            return isAdmin;

        }
        public List<User_Key_Mapping> GetAllActiveUsers()
        {
            List<User_Key_Mapping> lstUsers = new List<User_Key_Mapping>();
            try
            {
                using (var ctx = new GRM_Security_Entities())
                {
                    var query = ctx.Users.Where(x => x.IsActive == true).Select(x => x).ToList();
                    foreach (var user in query)
                    {
                        User_Key_Mapping data = new User_Key_Mapping();
                        data.UserName = user.UserName;
                        data.UserKey = user.UserRemoteKey.HasValue == true ? user.UserRemoteKey.Value.ToString() : Guid.Empty.ToString();
                        lstUsers.Add(data);
                    }
                }

            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return lstUsers;
        }



        #region GenieFinancials

        public CrowdUserObj AuthenticateUserFromCrowdFor_GenieFinancials(string UserName, string Password, bool OverridePassword = false)
        {
            var exc = new Exception("in: AuthenticateUserFromCrowdForGenieFinancials");
            Afiniti.GRM.SecurityDTO.CrowdUserObj crowdUserObj = new CrowdUserObj()
            {
                AuthenticationCode = 2,
                ApprovalStatus = 1
            };
            try
            {
                Utilities.WriteTrace("AuthenticateGenieFinancials_Start");
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                    ConfigurationManager.AppSettings["CrowdAppName"],
                    ConfigurationManager.AppSettings["CrowdAppPass"]);
                var res = crowdService.CreateCrowdToken_internal(UserName, Password, OverridePassword);
                if (res)
                {
                    crowdUserObj.AuthenticationCode = 1;
                    exc = new Exception(UserName + " Authenticated from crowd");
                    using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                    {
                        Utilities.WriteTrace("AuthenticateGenieFinancials_CrowdVerStart");
                        IQueryable<User> users = ctx.Users.Where(x => x.UserName.ToLower() == UserName.ToLower()
                                                                      && x.IsActive == true);
                        Expression<Func<User, bool>> approvalCriteria =
                            Utilities.CreateApprovalCriteria(GetApprovalPropertyNameByEndPoint());

                        users = users.Where(approvalCriteria);
                        var user = users.FirstOrDefault();
                        if (user != null)
                        {
                            exc = new Exception(UserName + " has been Authenticated from Security Service for GenieFinancials");
                            crowdUserObj.RemoteKey = user.UserRemoteKey.ToString();
                            crowdUserObj.UserKey = user.UserKey.ToString();
                            crowdUserObj.ApprovalStatus = user.GenieMobileApproval;
                            crowdUserObj.UserName = user.UserName;
                            crowdUserObj.Email = user.Email;

                            crowdUserObj.CrowdSSOToken = crowdService.CROWD_TOKEN;//"test";// 
                            crowdUserObj.JSessionID = crowdService.CROWD_JSESSIONID;
                            crowdUserObj.AuthenticationMetaData =
                                EncryptionClass.Encrypt_Decrypt(
                                    ConfigurationManager.AppSettings["JSessionIDCookieName"] + "=" +
                                    crowdService.CROWD_JSESSIONID + ";" +
                                    ConfigurationManager.AppSettings["CrowdTokenCookieName"] + "=" +
                                    crowdService.CROWD_TOKEN, true);
                            Utilities.WriteTrace("AuthenticateGenieFinancials_CrowdVerificationDone");
                        }
                        else
                        {
                            Utilities.WriteTrace("AuthenticateGenieFinancials_CrowdVerFailed");
                            exc = new Exception(UserName + " Could not be Authenticated from Security Service for GenieFinancials");
                        }
                    }
                }
                else
                {
                    Utilities.WriteTrace("AuthenticateGenieFinancials_CrowdTokenException");
                    exc = new Exception(UserName + " Could not be Authenticated from CROWD for GenieFinancials");
                }
            }
            catch (Exception ex)
            {
                Utilities.WriteTrace("AuthenticateGenieFinancials_CrowdVerificationMainException");
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }

            return crowdUserObj;
        }

        public CrowdUserObj GetUserRemoteKeyByEmailOnly_GenieFinancials(string Email)
        {
            CrowdUserObj crowdUserObj = new CrowdUserObj()
            {
                AuthenticationCode = 2
            };
            try
            {
                if (String.IsNullOrEmpty(Email))
                {
                    return crowdUserObj;
                }
                using (GRM_Security_Entities ctx = new GRM_Security_Entities())
                {
                    Exception exc;
                    var user = ctx.Users.Where(x => x.Email != null).FirstOrDefault(y => y.Email.ToLower() == Email.ToLower());
                    if (user != null)
                    {
                        crowdUserObj.RemoteKey = user.UserRemoteKey?.ToString();
                        crowdUserObj.UserKey = user.UserKey.ToString();
                        crowdUserObj.ApprovalStatus = user.GenieMobileApproval;
                        crowdUserObj.UserName = user.UserName;
                        crowdUserObj.Email = user.Email;
                        if (user.UserRemoteKey == null)
                        {
                            exc = new Exception("UserRemoteKey is null against the email: " + Email);
                            Utilities.WriteTrace("UserRemoteKey is null against the email: " + Email);
                        }
                    }
                    else
                    {
                        exc = new Exception("User could not be found with email: " + Email);
                        Utilities.WriteTrace("User could not be found with email: " + Email);
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
                crowdUserObj = null;
            }

            return crowdUserObj;
        }

        public void SendApprovalRequestEmail_GenieFinancials(string UserName, string Message)
        {
            SendRequestEmail(UserName, Message);
        }

        public bool RemoveSSOTokenFromCrowd_GenieFinancials(string CrowdSSOToken)
        {
            bool blnRemoved = false;

            try
            {
                CrowdAuthenticationService crowdService = new CrowdAuthenticationService(ConfigurationManager.AppSettings["CrowdURL"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppName"],
                                                                                     ConfigurationManager.AppSettings["CrowdAppPass"]);
                blnRemoved = crowdService.DeleteSession(CrowdSSOToken);
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return blnRemoved;
        }



        #endregion GenieFinancials

    }
}
