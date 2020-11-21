using System.Web.Mvc;
using ProjectBlake.Models;

namespace ProjectBlake.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Title = "Home Page";
            return View();
        }

        public ActionResult Consent()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ConsentRedirect()
        {
            return Redirect(DocuSignModel.Default().ConsentUrl);
        }

        [HttpPost]
        public ActionResult Logout()
        {
            Session.Clear();
            return RedirectToAction("Index", "Home");
        }
    }
}
