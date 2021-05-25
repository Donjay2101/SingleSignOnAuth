using SingleSignOnAuth;
using System.Diagnostics;
using System.Threading;
using System.Web.Mvc;

namespace WebApplication6.Controllers
{

    [SSOAuthenticate]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var d = HttpContext.User as SSOPrincipal;
            if (d != null)
            {
                Debug.WriteLine(Thread.CurrentPrincipal.Identity);
            }

            return View();
           
        }

       
        public ActionResult SSOAuthenticate()
        {
            return RedirectToAction("Index");
        }


        [AllowAnonymous]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}