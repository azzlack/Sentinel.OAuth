namespace Sentinel.Sample.Controllers
{
    using System.Web.Mvc;

    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return this.View();
        }

        [Authorize]
        public ActionResult Profile()
        {
            return this.View();
        }
    }
}