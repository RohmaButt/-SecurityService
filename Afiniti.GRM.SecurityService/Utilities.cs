using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Collections.Specialized;
using System.Text;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using Afiniti.Framework.LoggingTracing;
using Afiniti.GRM.Shared;

namespace Afiniti.GRM.SecurityService
{
    public static class Utilities
    {
        private static StringCollection eMessages = new StringCollection();

        public static void LogException(Exception pEx, string pString)
        {
            pString = String.IsNullOrEmpty(pString) ? "Security Service" : pString;
            WriteException(pEx, pString);
            Log.WriteLog(eMessages, pString);
        }
        private static void WriteException(Exception ex, String CallerName = "Security Service")
        {
            StringBuilder sbTrace = new StringBuilder();
            sbTrace.AppendLine("-----------------------------------------------------------------------------");
            sbTrace.AppendLine("Caller -- " + CallerName);

            sbTrace.AppendLine(DateTime.Now.ToString()).AppendLine("");

            if (ex.GetType() != null)
                sbTrace.AppendLine(ex.GetType().ToString());

            sbTrace.AppendLine(ex.Message);
            sbTrace.AppendLine(ex.StackTrace);


            eMessages.Add(sbTrace.ToString());
            Exception inner = ex.InnerException;

            if (inner != null)
            {
                WriteException(inner, CallerName);
            }
        }
        public static void WriteTrace(string traceMessage = "", string userName = "", [CallerMemberName] string methodName = "", [CallerLineNumber] int lineNumber = 0)
        {
            ApplicationTrace.Log(userName + " == " + methodName + " : " + lineNumber, traceMessage, Status.Started);
        }

        //public string GetServiceErrorGuid(Exception ex)
        //{
        //    Type exceptionType = pEx.GetType();
        //    string gGUID = "000000-000000-000000-000000";

        //    if (exceptionType.IsGenericType && exceptionType.GetGenericTypeDefinition() == typeof(FaultException<>))
        //    {
        //        GenericError gError = ErrorClass.GetMessageFromFault(pEx);
        //        eMessages.Add("-------------------------------------------------------");
        //        eMessages.Add("Service Call -- " + pString);
        //        eMessages.Add(DateTime.Now.ToString());
        //        eMessages.Add("");
        //        eMessages.Add("Error Code: " + gError.ErrorCode);
        //        eMessages.Add("Error GUID: " + gError.GUID);
        //        eMessages.Add("Error Message: " + gError.ErrorMessage);
        //        eMessages.Add("-------------------------------------------------------");

        //        if (gError.GUID != null)
        //            gGUID = gError.GUID;

        //        //Log.WriteLog(eMessages, pString);
        //    }
        //    return gGUID;
        //}
        public static Expression<Func<User, bool>> CreateApprovalCriteria(string PropertyName)
        {
            var ex = new Exception("PropertyName: " + PropertyName);
            Utilities.WriteTrace("PropertyName: " + PropertyName);
            Expression<Func<User, bool>> predicate = null;
            try
            {
               

                ParameterExpression userParam = Expression.Parameter(typeof(User));
                short approvedStatus = (short)ApprovalStatus.Approved;
                Expression aLeft = Expression.PropertyOrField(userParam, PropertyName);
                Expression aRight = Expression.Constant(approvedStatus,typeof(short));
                Expression makeEqualApproved = Expression.Equal(aLeft, aRight);
                predicate = Expression.Lambda<Func<User, bool>>(makeEqualApproved, userParam);

            }
            catch (Exception exc)
            {
                Utilities.LogException(exc, "");
                Utilities.LogException(new Exception("CreateApprovalCriteria -- Some Error Occurred during creation of Approval Criteria, Going to retry with default criteria"), "");
                ParameterExpression userParam = Expression.Parameter(typeof(User));
                short? approvedStatus = (short)ApprovalStatus.Approved;
                Expression aLeft = Expression.PropertyOrField(userParam, "ApprovalStatus");
                Expression aRight = Expression.Constant(approvedStatus);
                Expression makeEqualApproved = Expression.Equal(aLeft, aRight);
                predicate = Expression.Lambda<Func<User, bool>>(makeEqualApproved, userParam);
            }
            ex = new Exception("Predicate: " + predicate);
            Utilities.WriteTrace("Predicate: " + predicate);
            return predicate;
        }
        

    }
}