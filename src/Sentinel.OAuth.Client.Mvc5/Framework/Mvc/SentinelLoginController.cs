namespace Sentinel.OAuth.Client.Mvc5.Framework.Mvc
{
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using System.Web;
    using System.Web.Mvc;

    using Common.Logging;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;

    using Sentinel.OAuth.Client.Interfaces;
    using Sentinel.OAuth.Client.Mvc5.Models;
    using Sentinel.OAuth.Core.Interfaces.Identity;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;

    using Constants = Sentinel.OAuth.Client.Models.Constants;

    public abstract class SentinelLoginController : Controller
    {
        /// <summary>The oauth client.</summary>
        private readonly IOAuthClient oauthClient;

        /// <summary>The logger.</summary>
        private readonly ILog log;

        /// <summary>The authentication context.</summary>
        private IAuthenticationManager Authentication => this.HttpContext.GetOwinContext().Authentication;

        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelLoginController" /> class.
        /// </summary>
        /// <param name="oauthClient">The oauth client.</param>
        /// <param name="log">The log.</param>
        protected SentinelLoginController(IOAuthClient oauthClient, ILog log)
        {
            this.oauthClient = oauthClient;
            this.log = log;
        }
        
        public virtual async Task<ActionResult> Index(string returnUrl = "")
        {
            this.Authentication.SignOut(Constants.DefaultAuthenticationType);
            this.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

            return this.View(new LoginModel() { ReturnUrl = returnUrl });
        }

        public virtual async Task<ActionResult> Index(LoginModel model)
        {
            ActionResult result = null;

            if (this.ModelState.IsValid)
            {
                var loginResult = await this.ProcessLogin(model);

                if (loginResult.IsAuthenticated)
                {
                    var returnUrl = "/";

                    if (!string.IsNullOrEmpty(model.ReturnUrl) && this.Url.IsLocalUrl(model.ReturnUrl))
                    {
                        returnUrl = model.ReturnUrl;
                    }

                    this.log.Debug($"User is already authenticated, redirecting to {returnUrl}");

                    result = this.Redirect(returnUrl);
                }
            }
            else
            {
                model.Password = "";
                model.Errors = this.ModelState.Keys.SelectMany(x => this.ModelState[x].Errors).Select(x => x.ErrorMessage).ToList();
            }

            if (this.Request.AcceptTypes.Contains("text/html"))
            {
                return result ?? this.View(model);
            }

            return new JsonResult() { Data = model };
        }

        /// <summary>Processes the login using the specified username and password.</summary>
        /// <param name="model">The login model.</param>
        /// <returns>An action result.</returns>
        public virtual async Task<ISentinelIdentity> ProcessLogin(LoginModel model)
        {
            AccessTokenResponse tokenResponse = null;

            try
            {
                tokenResponse = await this.oauthClient.Authenticate(model.Username, model.Password, new[] { "openid" });
            }
            catch (HttpRequestException ex)
            {
                this.log.Error(ex);

                this.ModelState.AddModelError("Common", "The server seems to be having some problems right now, please try again later");

                return SentinelIdentity.Anonymous;
            }
            catch (Exception ex)
            {
                this.log.Error(ex);
            }

            if (string.IsNullOrEmpty(tokenResponse?.AccessToken))
            {
                this.ModelState.AddModelError("Common", "Username or password is invalid");

                return SentinelIdentity.Anonymous;
            }

            return await this.ProcessTokenResponse(tokenResponse, model.RememberMe, model.ReturnUrl);
        }

        /// <summary>Process the token response from the API.</summary>
        /// <param name="tokenResponse">The access token response.</param>
        /// <param name="rememberMe">true to remember login.</param>
        /// <param name="returnUrl">The return url.</param>
        /// <returns>A Task.</returns>
        private async Task<ISentinelIdentity> ProcessTokenResponse(AccessTokenResponse tokenResponse, bool rememberMe, string returnUrl)
        {
            // Log in using Sentinel authentication handler
            if (!string.IsNullOrEmpty(tokenResponse.IdToken))
            {
                var jwt = new JsonWebToken(tokenResponse.IdToken);

                var props = new AuthenticationProperties()
                {
                    IsPersistent = rememberMe,
                    RedirectUri = returnUrl
                };

                // Create identity
                var cookieIdentity = jwt.ToIdentity(DefaultAuthenticationTypes.ApplicationCookie).ToClaimsIdentity();
                cookieIdentity.AddClaim(new Claim("access_token", tokenResponse.AccessToken));

                // Sign in temporarily
                this.Authentication.SignIn(props, cookieIdentity);

                return new SentinelIdentity(cookieIdentity);
            }

            this.log.Warn($"No id_token received, unable to log in using {DefaultAuthenticationTypes.ApplicationCookie}");

            return SentinelIdentity.Anonymous;
        }
    }
}