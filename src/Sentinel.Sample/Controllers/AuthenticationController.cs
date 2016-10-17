namespace Sentinel.Sample.Controllers
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Web;
    using System.Web.Mvc;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;
    
    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation.Providers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.Sample.Managers;
    using Sentinel.Sample.ViewModels;

    public class AuthenticationController : Controller
    {
        private readonly IUserManager userManager;

        private IAuthenticationManager Authentication => this.HttpContext.GetOwinContext().Authentication;

        public AuthenticationController()
        {
            this.userManager = new SimpleUserManager(new PBKDF2CryptoProvider(), new AsymmetricCryptoProvider());
        }

        [Route("authentication/login")]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl = "")
        {
            // If we are already logged in, just redirect to the returnUrl
            if (this.Authentication.User.Identity.IsAuthenticated)
            {
                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) && returnUrl != "/authentication/login")
                {
                    return this.Redirect(returnUrl);
                }
            }

            return this.View(new CookieLoginViewModel() { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Route("authentication/login")]
        public async Task<ActionResult> Login(CookieLoginViewModel model)
        {
            var user = await this.userManager.AuthenticateUserWithPasswordAsync(model.Username, model.Password);

            if (user.Identity.IsAuthenticated)
            {
                var cookieIdentity = new SentinelIdentity(DefaultAuthenticationTypes.ApplicationCookie, user.Identity);

                this.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                this.Authentication.SignIn(
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1),
                        RedirectUri = model.ReturnUrl
                    },
                    cookieIdentity.ToClaimsIdentity());

                if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                {
                    return this.Redirect(model.ReturnUrl);
                }
            }

            return this.View(model);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        [Route("authentication/logout")]
        public ActionResult Logout(string returnUrl = "")
        {
            this.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return this.Redirect(returnUrl);
            }

            return this.RedirectToAction("Index", "Home");
        }
    }
}