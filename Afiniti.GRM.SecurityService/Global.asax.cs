using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.SessionState;
using System.ServiceModel;
using System.Web.Routing;
using System.ServiceModel.Activation;
using System.Web.Mvc;
using System.Configuration;

namespace Afiniti.GRM.SecurityService
{
    public class Global : System.Web.HttpApplication
    {

        protected void Application_Start(object sender, EventArgs e)
        {
            try
            {
                RouteTable.Routes.Add(new ServiceRoute(ConfigurationManager.AppSettings["CustomRouteForREST"].ToString(), new WebServiceHostFactory(), typeof(SecurityService)));
                
            }
            catch(Exception ex)
            {
                Utilities.LogException(ex, "");
            }
           
        }

        protected void Session_Start(object sender, EventArgs e)
        {

        }

        protected void Application_BeginRequest(object sender, EventArgs e)
        {
            
        }

        protected void Application_AuthenticateRequest(object sender, EventArgs e)
        {

        }

        protected void Application_Error(object sender, EventArgs e)
        {

        }

        protected void Session_End(object sender, EventArgs e)
        {

        }

        protected void Application_End(object sender, EventArgs e)
        {

        }
    }
}