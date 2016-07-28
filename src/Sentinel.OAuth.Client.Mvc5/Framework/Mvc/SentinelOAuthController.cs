namespace Sentinel.OAuth.Client.Mvc5.Framework.Mvc
{
    using System;
    using System.Threading.Tasks;
    using System.Web;
    using System.Web.Mvc;

    using Common.Logging;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;

    using Sentinel.OAuth.Client.Mvc5.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;

    public abstract class SentinelOAuthController : Controller
    {
        private readonly ILog log;

        /// <summary>The authentication context.</summary>
        private IAuthenticationManager Authentication => this.HttpContext.GetOwinContext().Authentication;

        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelOAuthController" /> class.
        /// </summary>
        protected SentinelOAuthController(ILog log)
        {
            this.log = log;
        }

        /// <summary>
        /// Provides the user with a consent screen where the user can decide whether to give the
        /// application access or not.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="model">The consent screen viewmodel.</param>
        /// <returns>An action result</returns>
        public virtual async Task<ActionResult> Index(OAuthLoginViewModel model)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model), "The request is invalid");
            }

            if (!this.Authentication.User.Identity.IsAuthenticated)
            {
                this.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);

                return new HttpUnauthorizedResult();
            }

            // Remove trailing slash if present
            if (this.Request.Url != null && this.Request.Url.AbsolutePath.EndsWith("/"))
            {
                return this.Redirect($"{this.Request.Url.Scheme}://{this.Request.Url.Authority}{this.Request.Url.AbsolutePath.TrimEnd('/')}{this.Request.Url.Query}");
            }

            return this.View(model);
        }

        /// <summary>Handles the user consent action.</summary>
        /// <param name="model">The consent screen viewmodel.</param>
        /// <returns>An action result</returns>
        public virtual async Task<ActionResult> Authorize(OAuthLoginViewModel model)
        {
            if (!this.ModelState.IsValid)
            {
                this.ModelState.AddModelError("Common", "Something went wrong when processing your request. Please try again later.");

                return await Task.FromResult(this.View("Index", model));
            }

            if (!this.Authentication.User.Identity.IsAuthenticated)
            {
                this.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);

                return await Task.FromResult(new HttpUnauthorizedResult());
            }

            if (!model.Grant)
            {
                return await Task.FromResult(this.Redirect($"{model.RedirectUri}?error=access_denied&error_description=User does not grant access"));
            }

            return this.View(model);
        }

        public virtual Task SignIn(OAuthLoginViewModel model)
        {
            var identity = new SentinelIdentity(OAuthDefaults.AuthenticationType, this.Authentication.User.Identity);

            this.Authentication.SignOut(OAuthDefaults.AuthenticationType);
            this.Authentication.SignIn(new AuthenticationProperties() { RedirectUri = model.RedirectUri }, identity.ToClaimsIdentity());

            return Task.FromResult<object>(null);
        }
    }
}