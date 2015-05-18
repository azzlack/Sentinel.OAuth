namespace Sentinel.Sample.Providers
{
    using System;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;

    using Sentinel.OAuth.Core.Interfaces.Providers;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;
    using Microsoft.AspNet.Identity;

    public class CustomAuthorizationServerOptions : SentinelAuthorizationServerOptions
    {
        private readonly IPrincipalProvider principalProvider;

        public CustomAuthorizationServerOptions(IPrincipalProvider principalProvider)
        {
            this.principalProvider = principalProvider;

            this.Events.TokenIssued += this.OnTokenIssued;
            this.Events.PrincipalCreated += this.OnPrincipalCreated;
            this.Events.UnknownGrantTypeReceived += this.OnUnknownGrantTypeReceived;
        }

        private async Task OnUnknownGrantTypeReceived(UnknownGrantTypeReceivedEventArgs args)
        {
            var context = (OAuthGrantCustomExtensionContext)args.Context;

            if (context.GrantType == "api_key")
            {
                // TODO: Add support for validating the provided api key from the <c>context.Parameters</c> object
            }
        }

        private async Task OnPrincipalCreated(PrincipalCreatedEventArgs args)
        {
            var principal = new SentinelPrincipal(args.Principal);

            // Add name identifier claim to support MVC AntiForgeryToken
            principal.Identity.AddClaim(ClaimTypes.NameIdentifier, principal.Identity.Name);

            // Replace principal to make Sentinel use the new principal for the access token
            args.Principal = principal;
        }

        private async Task OnTokenIssued(TokenIssuedEventArgs args)
        {
            var context = (OAuthTokenEndpointResponseContext)args.Context;

            // Create new principal for cookie authentication
            var cookiePrincipal = this.principalProvider.Create(DefaultAuthenticationTypes.ApplicationCookie, context.Identity.Claims.Select(x => new SentinelClaim(x)).ToArray());

            // Log in using cookie authenticator
            context.Request.Context.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            context.Request.Context.Authentication.SignIn(
                new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTime.UtcNow.Add(context.Options.AccessTokenExpireTimeSpan)
                },
                cookiePrincipal.Identity.AsClaimsIdentity());
        }
    }
}