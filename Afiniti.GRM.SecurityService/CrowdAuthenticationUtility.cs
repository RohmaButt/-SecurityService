using Afiniti.GRM.SecurityDTO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Web;

namespace Afiniti.GRM.SecurityService
{
    public class CrowdAuthenticationService
    {
        /// <summary>
        /// Instatiate the authentication service
        /// </summary>
        /// <param name="crowdUrl">Url of the hosted Crowd instance</param>
        /// <param name="applicationName">The application name set in Crowd</param>
        /// <param name="applicationPassword">The password for the respective application set in Crowd</param>
        public CrowdAuthenticationService(string crowdUrl, string applicationName, string applicationPassword)
        {
            CROWD_URL = crowdUrl;
            APPLICATION_NAME = applicationName;
            APPLICATION_PASSWORD = applicationPassword;
        }
        public CrowdAuthenticationService()
        {
            CROWD_URL = ConfigurationManager.AppSettings["CrowdURL"];
            APPLICATION_NAME = ConfigurationManager.AppSettings["CrowdAppName"];
            APPLICATION_PASSWORD = ConfigurationManager.AppSettings["CrowdAppPass"];
        }

        #region Global Variables
        public string USER_KEY = string.Empty;
        private string APPLICATION_NAME = string.Empty;
        private string APPLICATION_PASSWORD = string.Empty;
        private string CROWD_URL = string.Empty;
        public string CROWD_TOKEN = string.Empty;
        public string CROWD_JSESSIONID = string.Empty;

        private string displayName = string.Empty;
        public string DisplayName
        {
            get => displayName;
            private set => displayName = string.Empty;
        }

        private string email = string.Empty;
        public string Email
        {
            get => email;
            private set => email = string.Empty;
        }

        private const string DISPLAY_NAME = "display-name";
        private const string EMAIL = "email";
        private const string CROWD_SESSION_KEY = "key";
        private const string TOKEN = "token";

        private const string LINK = "link";
        private const string HREF = "href";

        #endregion

        /// <summary>
        /// Authenticate against Crowd via REST API
        /// </summary>
        /// <param name="username">The username of the user that is set in Crowd</param>
        /// <param name="password">The password of the user that is set in Crowd</param>
        /// <returns>Returns TRUE if the user has provided correct credentials. False otherwise</returns>
        /// <remarks>Throws WebException if authentication fails</remarks>
        public bool Authenticate(string username, string password)
        {
            Exception exc = new Exception("I am in Authenticate");
            //Utilities.LogException(exc, "");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/latest/authentication?username=" + username);
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Method = "POST";
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));

            using (var writer = new StreamWriter(request.GetRequestStream()))
            {
                var json = JsonConvert.SerializeObject(
                    new
                    {
                        value = password
                    });
                writer.Write(json);
            }
            try
            {
                exc = new Exception("Sending request to CrowdURL");
                //Utilities.LogException(exc, "");
                var result = (HttpWebResponse)request.GetResponse();
                exc = new Exception("CrowdURL result StatusCode is: " + result.StatusCode);
                //Utilities.LogException(exc, "");
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    using (var reader = new StreamReader(result.GetResponseStream()))
                    {
                        string strRes = reader.ReadToEnd();
                        var json = JsonConvert.DeserializeObject<Dictionary<string, object>>(strRes);
                        //foreach (var key in json.Keys)
                        //{
                        //    object obj;
                        //    bool flag = json.TryGetValue(key, out obj);
                        //    if (flag)
                        //    {
                        //        exc = new Exception(key + " : " + obj.ToString());
                        //        Utilities.LogException(exc, "");
                        //    }
                        //}
                        displayName = json[DISPLAY_NAME].ToString();
                        email = json[EMAIL].ToString();
                        USER_KEY = json[CROWD_SESSION_KEY].ToString();
                    }

                    return true;
                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
                return false;
            }
            exc = new Exception("Unauthorized");
            //Utilities.LogException(exc, "");
            return false;
        }

        public CrowdUserObj GetUserObjectByToken(string CrowdSSOToken)
        {
            Exception exc = new Exception("I am in GetUserObjectByToken: ");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/latest/session/" + CrowdSSOToken);
            request.ContentType = "application/json";
            request.Accept = "application/json";
            //request.Method = "GET";
            request.Method = "POST";
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));
            CrowdUserObj crowdUser = new CrowdUserObj();
            try
            {
                exc = new Exception(request.Address.ToString() + "  --  " + request.RequestUri.ToString());
                using (var writer = new StreamWriter(request.GetRequestStream()))
                {
                    var expandedObj = "{" +
                                        "\"validationFactors\": [{" +
                                        "\"name\": \"remote_address\"," +
                                        "\"value\": \"" + GetIPAddress() + "\"" +
                                        "}]" +
                                     "}";
                    writer.Write(expandedObj);
                }

                var result = (HttpWebResponse)request.GetResponse();
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    CROWD_JSESSIONID = GetJSessionCookieValue(result.Headers.Get("Set-Cookie"));
                    using (var reader = new StreamReader(result.GetResponseStream()))
                    {
                        string strRes = reader.ReadToEnd();
                        var json = JsonConvert.DeserializeObject<Dictionary<string, object>>(strRes);
                        foreach (var key in json.Keys)
                        {
                            object obj;
                            bool flag = json.TryGetValue(key, out obj);
                            if (flag)
                            {
                                if (key == "user")
                                {
                                    var jsonUserObject = JsonConvert.DeserializeObject<Dictionary<string, object>>(obj.ToString());
                                    crowdUser.UserName = jsonUserObject["name"].ToString();
                                    Utilities.WriteTrace("crowdUser.UserName: " + crowdUser.UserName);

                                }
                            }
                        }
                    }
                    crowdUser.JSessionID = CROWD_JSESSIONID;
                    Utilities.WriteTrace("CROWD_JSESSIONID: " + CROWD_JSESSIONID);

                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
                return crowdUser;
            }
            exc = new Exception("Username from crowd is : " + crowdUser.UserName + " : " + crowdUser.CrowdSSOToken + " : " + crowdUser.JSessionID);
            //Utilities.LogException(exc, "");
            return crowdUser;
        }

        public bool CreateCrowdToken_internal(string username, string password, bool overridePassword = false)
        {
            string ip = GetIPAddress();
            Utilities.WriteTrace("IPs are");
            Utilities.WriteTrace(ip);
            Exception exc = new Exception("I am in CreateCrowdToken");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/latest/session" + (overridePassword == true ? "?validate-password=false" : ""));
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Method = "POST";
            // request.ContentLength = postString.Length;
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));
            try
            {
                using (var writer = new StreamWriter(request.GetRequestStream()))
                {
                    var expandedObj = "{" +
                                          "\"username\": \"" + username + "\"," +
                                          "\"password\": \"" + password + "\"," +
                                          "\"validation-factors\": {" +
                                                  "\"validationFactors\": [{" +
                                                  "\"name\": \"remote_address\"," +
                                                  "\"value\": \"" + GetIPAddress() + "\"" +
                                                  "}]" +
                                            "}" +
                                      "}";

                    var obj = "{ \"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
                    writer.Write(expandedObj);
                }
                var result = (HttpWebResponse)request.GetResponse();
                if (result.StatusCode == HttpStatusCode.Created)
                {
                    CROWD_JSESSIONID = GetJSessionCookieValue(result.Headers.Get("Set-Cookie"));

                    using (var reader = new StreamReader(result.GetResponseStream()))
                    {
                        string strRes = reader.ReadToEnd();
                        var json = JsonConvert.DeserializeObject<Dictionary<string, object>>(strRes);

                        CROWD_TOKEN = json[TOKEN].ToString();
                        //DisplayName = json[DISPLAY_NAME].ToString();
                        //exc = new Exception(strRes);
                        //Utilities.LogException(exc, "");
                    }
                    Utilities.WriteTrace("Crowd Token is : " + CROWD_TOKEN);
                    return true;
                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
                return false;
            }
            exc = new Exception("CROWD request Unauthorized of: " + username);
            return false;
        }

        public UserObj GetUserFromCrowd(string username)
        {
            UserObj user = new UserObj();
            String displayName = "";
            String avatarURL = "";
            Exception exc = new Exception("I am here to get user");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/1/user?username=" + username);
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Method = "Get";
            // request.ContentLength = postString.Length;
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));
            try
            {
                exc = new Exception(request.Address.ToString() + "  --  " + request.RequestUri.ToString());
                var result = (HttpWebResponse)request.GetResponse();
                exc = new Exception("response received:  " + result.ToString());
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    CROWD_JSESSIONID = GetJSessionCookieValue(result.Headers.Get("Set-Cookie"));
                    using (var reader = new StreamReader(result.GetResponseStream()))
                    {
                        string strRes = reader.ReadToEnd();
                        var json = JsonConvert.DeserializeObject<Dictionary<string, object>>(strRes);
                        displayName = json[DISPLAY_NAME].ToString();
                        var link = JsonConvert.DeserializeObject<Dictionary<string, object>>(json[LINK].ToString());
                        avatarURL = link[HREF].ToString();

                        user.DisplayName = displayName;
                        user.AvatarURL = avatarURL;
                        exc = new Exception("Display Name received: : " + displayName + " : " + avatarURL);
                    }
                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
            }
            exc = new Exception("GetUserFromCrowd " + username);
            return user;
        }

        public string GetEmailAddressFromUserToken(string token)
        {
            string useremail = "";
            Exception exc = new Exception("I am here to get user");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/latest/session/" + token);
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Method = "Get";
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));
            try
            {
                exc = new Exception(request.Address.ToString() + "  --  " + request.RequestUri.ToString());
                var result = (HttpWebResponse)request.GetResponse();
                exc = new Exception("response received:  " + result.ToString());
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    using (var reader = new StreamReader(result.GetResponseStream()))
                    {
                        string strRes = reader.ReadToEnd();
                        var json = JsonConvert.DeserializeObject<Dictionary<string, object>>(strRes);
                        foreach (var key in json.Keys)
                        {
                            object obj;
                            bool flag = json.TryGetValue(key, out obj);
                            if (flag)
                            {
                                if (key == "user")
                                {
                                    var jsonUserObject = JsonConvert.DeserializeObject<Dictionary<string, object>>(obj.ToString());
                                    foreach (KeyValuePair<string, object> d in jsonUserObject)
                                    {
                                        if (d.Key == "email")
                                        {
                                            Utilities.WriteTrace("crowdUser email id: " + d.Value.ToString().ToLower());
                                            useremail = d.Value?.ToString().ToLower();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
            }
            exc = new Exception("GetUserFromCrowd " + token);
            return useremail;
        }

        public UserObj GetUserAvatarFromCrowd(string username)
        {
            UserObj user = new UserObj();
            String displayName = "";
            String avatarURL = "";
            Exception exc = new Exception("I am here to get user avatar");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/1/user/avatar?username=" + username);
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Method = "Get";
            // request.ContentLength = postString.Length;
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));
            try
            {
                exc = new Exception(request.Address.ToString() + "  --  " + request.RequestUri.ToString());
                //Utilities.LogException(exc, ""); 

                var result = (HttpWebResponse)request.GetResponse();
                exc = new Exception("response received:  " + result.ToString());
                //Utilities.LogException(exc, "");


                if (result.StatusCode == HttpStatusCode.OK)
                {
                    CROWD_JSESSIONID = GetJSessionCookieValue(result.Headers.Get("Set-Cookie"));

                    using (var reader = new StreamReader(result.GetResponseStream()))
                    {
                        string strRes = reader.ReadToEnd();
                        var json = JsonConvert.DeserializeObject<Dictionary<string, object>>(strRes);


                        displayName = json[DISPLAY_NAME].ToString();

                        var link = JsonConvert.DeserializeObject<Dictionary<string, object>>(json[LINK].ToString());
                        avatarURL = link[HREF].ToString();

                        user.DisplayName = displayName;
                        user.AvatarURL = avatarURL;

                        exc = new Exception("Display Name received: : " + displayName + " : " + avatarURL);
                        //Utilities.LogException(exc, "");
                    }
                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
            }

            exc = new Exception("GetUserAvatarFromCrowd " + username);
            //Utilities.LogException(exc, "");
            return user;
        }

        private string GetJSessionCookieValue(string cookieString)
        {
            string str = "";

            try
            {
                if (!String.IsNullOrEmpty(cookieString))
                {
                    var tokenized = cookieString.Split(new string[] { "JSESSIONID=" }, StringSplitOptions.None);
                    if (tokenized.Length > 1)
                    {
                        str = tokenized[1].Trim().Substring(0, 31);
                    }
                }
            }
            catch (Exception ex)
            {
                Utilities.LogException(ex, "");
            }
            return str;
        }
        public bool DeleteSession(string CrowdSSOToken)
        {
            Exception exc = new Exception("I am in DeleteSessions");
            var request = (HttpWebRequest)WebRequest.Create(CROWD_URL + "/usermanagement/latest/session/" + CrowdSSOToken);
            request.ContentType = "application/json";
            request.Accept = "application/json";
            request.Method = "DELETE";
            request.Headers[HttpRequestHeader.Authorization] = string.Format("Basic " + Encode(APPLICATION_NAME, APPLICATION_PASSWORD));
            try
            {

                var result = (HttpWebResponse)request.GetResponse();
                if (result.StatusCode == HttpStatusCode.NoContent)
                {

                    return true;
                }
            }
            catch (WebException ex)
            {
                Utilities.LogException(ex, "");
                return false;
            }
            //exc = new Exception("Unable to remove SSO token");
            //Utilities.LogException(exc, "");
            return false;
        }
        #region Private Methods

        private static string Encode(string username, string password)
        {
            var auth = string.Join(":", username, password);
            return Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(auth));
        }
        private string GetIPAddress()
        {
            return ConfigurationManager.AppSettings["CrowdServerIP"];
        }

        #endregion
    }
}