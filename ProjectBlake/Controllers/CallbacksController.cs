using System;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ProjectBlake.Common;
using ProjectBlake.Models;

namespace ProjectBlake.Models
{
    //new { codeLocal, authGrantTokenContent, userContent, jwtResult.token, jwtResult.content }
}

namespace ProjectBlake.Controllers
{
    public class CallbacksController : Controller
    {
        public async Task<ActionResult> Docusign([FromUri] string code)
        {
            // what is this "code" value they are sending us after the "impersonation" scope??
            // per DS, we can ignore `code` if using the JWT flow
            ViewBag.Title = "DocuSign JWT Callback";

            string codeLocal = code;
            string authGrantTokenContent;

            bool isLoggedIn = Convert.ToBoolean(Session["isLoggedIn"]);
            if (isLoggedIn)
            {
                codeLocal = null;
                authGrantTokenContent = Session["authGrantTokenResponse"].ToString();
            }
            else
            {
                authGrantTokenContent = await DocuSignToken.GetAuthGrantAccessToken(code);

                Session["authGrantTokenResponse"] = authGrantTokenContent;
                Session["isLoggedIn"] = true;
            }

            if (!string.IsNullOrWhiteSpace(authGrantTokenContent))
            {
                var userContent = await DocuSignToken.GetOauthUser(authGrantTokenContent);
                var userJToken = JToken.Parse(userContent);
                string userId = userJToken["sub"].ToString();

                dynamic jwtResult = await DocuSignToken.BuildJwtAndExchangeWithDocusign(userId);

                authGrantTokenContent = JToken.Parse(authGrantTokenContent).ToString(Formatting.Indented);
                return View(new DocusignViewModel(codeLocal, authGrantTokenContent, userContent, jwtResult.token, jwtResult.content));
            }

            return RedirectToAction("Index", "Home");
        }

    }
}
