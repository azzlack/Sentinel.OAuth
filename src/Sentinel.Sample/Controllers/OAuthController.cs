namespace Sentinel.Sample.Controllers
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Web;
    using System.Web.Mvc;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;

    using Sentinel.OAuth.Core.Interfaces.Managers;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Implementation.Managers;
    using Sentinel.OAuth.Models.Identity;
    using Sentinel.Sample.Managers;
    using Sentinel.Sample.ViewModels;

    public class OAuthController : Controller
    {
        private IClientManager clientManager;

        private IAuthenticationManager Authentication => this.HttpContext.GetOwinContext().Authentication;

        public OAuthController()
        {
            this.clientManager = new SimpleClientManager();
        }

        [Route("oauth/authorize")]
        public async Task<ActionResult> Authorize(OAuthAuthorizeViewModel model)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model), "The request is invalid");
            }

            // Redirect to login page if user is not already logged in
            if (!this.Authentication.User.Identity.IsAuthenticated)
            {
                this.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);

                return new HttpUnauthorizedResult();
            }

            // Remove trailing slash if present
            if (this.Request.Url != null && this.Request.Url.AbsolutePath.EndsWith("/"))
            {
                return
                    this.Redirect(
                        $"{this.Request.Url.Scheme}://{this.Request.Url.Authority}{this.Request.Url.AbsolutePath.TrimEnd('/')}{this.Request.Url.Query}");
            }

            var client = await this.clientManager.AuthenticateClientAsync(model.ClientId, model.RedirectUri);

            if (client.Identity.IsAuthenticated)
            {
                return this.View(model);
            }

            return await Task.FromResult(this.Redirect($"{model.RedirectUri}?error=unauthorized_client&error_description=The client is invalid&state={model.State}"));
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route("oauth/authorize")]
        public async Task<ActionResult> AuthorizeClient(OAuthAuthorizeViewModel model)
        {
            if (!this.ModelState.IsValid)
            {
                return await Task.FromResult(this.View("Authorize", model));
            }

            // Redirect user back to application with an error message if it rejects 
            if (!model.Grant)
            {
                return await Task.FromResult(this.Redirect($"{model.RedirectUri}?error=access_denied&error_description=User does not grant access&state={model.State}"));
            }

            // Redirect user if it is no longer authenticated
            if (!this.Authentication.User.Identity.IsAuthenticated)
            {
                this.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);

                return await Task.FromResult(new HttpUnauthorizedResult());
            }

            // Log in user with new authentication type
            var identity = new SentinelIdentity(OAuthDefaults.AuthenticationType, this.Authentication.User.Identity);

            this.Authentication.SignOut(OAuthDefaults.AuthenticationType);
            this.Authentication.SignIn(identity.AsClaimsIdentity());

            return await Task.FromResult(new EmptyResult());
        }
    }
}