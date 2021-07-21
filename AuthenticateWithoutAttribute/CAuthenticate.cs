using SingleSignOnAuth;
using System.Web;
using System.Web.Mvc;

namespace AuthenticateWithoutAttribute
{
    public class CAuthenticate:AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            return Authenticator.Instance.IsAuthenticated(httpContext);
        }
    }
}