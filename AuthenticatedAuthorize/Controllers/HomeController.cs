using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace AuthenticatedAuthorize.Controllers
{
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
			return View();
		}

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

		[Authorize]
		public ActionResult TestPage()
		{
			return View();
		}

		public ActionResult Logout()
		{
			FormsAuthentication.SignOut();
			return RedirectToRoute("Default", new { controller = "Home", action = "TestPage" });
		}

		public ActionResult Login()
		{
			string loginName = Request.Form["loginName"];
			if (string.IsNullOrEmpty(loginName))
			return RedirectToRoute("Default", new { controller = "Home", action = "TestPage" });
			FormsAuthentication.SetAuthCookie(loginName, true);
			return RedirectToRoute("Default", new { controller = "Home", action = "TestPage" });
		}

		public ActionResult TestPage2()
		{
			return View();
		}
	}
}