namespace Sentinel.OAuth.Client.Mvc5.Framework.Mvc
{
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using System.Web;
    using System.Web.Mvc;

    using Common.Logging;

    using Microsoft.AspNet.Identity;
    using Microsoft.Owin.Security;

    using Sentinel.OAuth.Client.Interfaces;
    using Sentinel.OAuth.Client.Mvc5.Models;
    using Sentinel.OAuth.Core.Models.OAuth.Http;
    using Sentinel.OAuth.Core.Models.Tokens;
    using Sentinel.OAuth.Extensions;

    public class SentinelAuthenticationController : Controller
    {
        /// <summary>The oauth client.</summary>
        private readonly IOAuthClient oauthClient;

        /// <summary>The logger.</summary>
        private readonly ILog log;

        /// <summary>The authentication context.</summary>
        private IAuthenticationManager Authentication => this.HttpContext.GetOwinContext().Authentication;

        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelAuthenticationController" /> class.
        /// </summary>
        /// <param name="oauthClient">The oauth client.</param>
        /// <param name="log">The log.</param>
        public SentinelAuthenticationController(IOAuthClient oauthClient, ILog log)
        {
            this.oauthClient = oauthClient;
            this.log = log;
        }
        
        public virtual async Task<ActionResult> Index(string returnUrl = "")
        {
            return this.View(new LoginModel() { ReturnUrl = returnUrl });
        }

        public virtual async Task<ActionResult> Index(LoginModel model)
        {
            if (this.ModelState.IsValid)
            {
                return await this.ProcessLogin(model);
            }

            model.Password = "";
            model.Errors = this.ModelState.Keys.SelectMany(x => this.ModelState[x].Errors).Select(x => x.ErrorMessage).ToList();

            return new JsonResult { Data = model };
        }

        /// <summary>Processes the login using the specified username and password.</summary>
        /// <param name="model">The login model.</param>
        /// <returns>An action result.</returns>
        public virtual async Task<ActionResult> ProcessLogin(LoginModel model)
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

                return this.View(model);
            }
            catch (Exception ex)
            {
                this.log.Error(ex);
            }

            if (string.IsNullOrEmpty(tokenResponse?.AccessToken))
            {
                this.ModelState.AddModelError("Common", "Username or password is invalid");

                return this.View(model);
            }

            if (await this.ProcessTokenResponse(tokenResponse, true, model.ReturnUrl))
            {
                if (!string.IsNullOrEmpty(model.ReturnUrl) && this.Url.IsLocalUrl(model.ReturnUrl))
                {
                    return this.Redirect(model.ReturnUrl);
                }

                return this.Redirect("/");
            }

            return this.View(model);
        }

        /// <summary>Process the token response from the API.</summary>
        /// <param name="tokenResponse">The access token response.</param>
        /// <param name="rememberMe">true to remember login.</param>
        /// <param name="returnUrl">The return url.</param>
        /// <returns>A Task.</returns>
        private async Task<bool> ProcessTokenResponse(AccessTokenResponse tokenResponse, bool rememberMe, string returnUrl)
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

                // Sign in temporarily
                this.Authentication.SignIn(props, cookieIdentity);

                return true;
            }
            else
            {
                this.log.Warn($"No id_token received, unable to log in using {DefaultAuthenticationTypes.ApplicationCookie}");
            }

            return false;
        }
    }
}