using Afiniti.GRM.SecurityDTO;
using System.Collections.Generic;
using System.Linq;
using System.Configuration;
using System;

namespace Afiniti.GRM.SecurityService
{
    public partial class SecurityService : ISecurityService_PMO
    {
        public CrowdUserObj AuthenticateUser_PMO(string UserName, string Password)
        {
            CrowdUserObj crowdUserObj = AuthenticateUserFromCrowdForPMO(UserName, Password); 

            return crowdUserObj;
        }
    }
}