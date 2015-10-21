namespace Sentinel.OAuth.Providers.OAuth
{
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.OAuth;
    using Sentinel.OAuth.Core.Constants.Identity;
    using Sentinel.OAuth.Core.Constants.OAuth;
    using Sentinel.OAuth.Core.Models;
    using Sentinel.OAuth.Extensions;
    using Sentinel.OAuth.Models.Identity;
    using System;
    using System.Linq;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    public class SentinelAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>Options for controlling the operation.</summary>
        private readonly SentinelAuthorizationServerOptions options;

        /// <summary>
        /// Initializes a new instance of the <see cref="SentinelAuthorizationServerProvider"/> class.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="options">The security handler.</param>
        public SentinelAuthorizationServerProvider(SentinelAuthorizationServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            this.options = options;
        }

        /// <summary>
        /// Called for each request to the Authorize endpoint to determine if the request is valid and should continue.
        /// The default behavior when using the OAuthAuthorizationServerProvider is to assume well-formed requests, with
        /// validated client redirect URI, should continue processing. An application may add any additional constraints.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task ValidateAuthorizeRequest(OAuthValidateAuthorizeRequestContext context)
        {
            this.options.Logger.Debug("Authorize request is valid");

            context.Validated();
        }

        /// <summary>
        /// Called for each request to the Token endpoint to determine if the request is valid and should continue. 
        ///             The default behavior when using the OAuthAuthorizationServerProvider is to assume well-formed requests, with 
        ///             validated client credentials, should continue processing. An application may add any additional constraints.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task ValidateTokenRequest(OAuthValidateTokenRequestContext context)
        {
            this.options.Logger.Debug("Token request is valid");

            // Store grant type in context
            context.OwinContext.GetOAuthContext().GrantType = context.TokenRequest.GrantType;

            context.Validated();
        }

        /// <summary>
        /// Called to validate that the context.ClientId is a registered "client_id", and that the context.RedirectUri a "redirect_uri"
        /// registered for that client. This only occurs when processing the Authorize endpoint. The application MUST implement this
        /// call, and it MUST validate both of those factors before calling context.Validated. If the context.Validated method is called
        /// with a given redirectUri parameter, then IsValidated will only become true if the incoming redirect URI matches the given redirect URI.
        /// If context.Validated is not called the request will not proceed further.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            this.options.Logger.DebugFormat("Validating client id and redirect uri");

            // Only proceed if client id and redirect uri is provided
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.RedirectUri))
            {
                this.options.Logger.WarnFormat("Client id ({0}) or client secret ({1}) is invalid", context.ClientId, context.RedirectUri);

                return;
            }

            this.options.Logger.DebugFormat("Authenticating client '{0}' and redirect uri '{1}'", context.ClientId, context.RedirectUri);

            var client = await this.options.ClientManager.AuthenticateClientAsync(context.ClientId, context.RedirectUri);

            if (!client.Identity.IsAuthenticated)
            {
                context.Rejected();

                this.options.Logger.WarnFormat("Client '{0}' and redirect uri '{1}' was not authenticated", context.ClientId, context.RedirectUri);

                return;
            }

            this.options.Logger.DebugFormat("Client '{0}' and redirect uri '{1}' was successfully authenticated", context.ClientId, context.RedirectUri);

            context.OwinContext.GetOAuthContext().ClientId = context.ClientId;
            context.OwinContext.GetOAuthContext().RedirectUri = context.RedirectUri;

            context.Validated(context.RedirectUri);
        }

        /// <summary>
        /// Called to validate that the origin of the request is a registered "client_id", and that the correct credentials for that client are
        /// present on the request. If the web application accepts Basic authentication credentials,
        /// context.TryGetBasicCredentials(out clientId, out clientSecret) may be called to acquire those values if present in the request header. If the web
        /// application accepts "client_id" and "client_secret" as form encoded POST parameters,
        /// context.TryGetFormCredentials(out clientId, out clientSecret) may be called to acquire those values if present in the request body.
        /// If context.Validated is not called the request will not proceed further.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            this.options.Logger.DebugFormat("Validating client id and secret");

            string clientId;
            string clientSecret;

            // Validate that redirect uri is specified
            // 'redirect_uri' must be specified for all calls that are not 'client_credentials' grants.
            if (context.Parameters["redirect_uri"] == null && context.Parameters["grant_type"] != "client_credentials")
            {
                context.SetError("invalid_request");

                this.options.Logger.ErrorFormat("Redirect URI was not specified, the token request is not valid");

                return;
            }

            if (context.TryGetBasicCredentials(out clientId, out clientSecret)
                || context.TryGetFormCredentials(out clientId, out clientSecret))
            {
                // Only proceed if client id and client secret is provided
                if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
                {
                    context.SetError("invalid_client");

                    this.options.Logger.WarnFormat("Client id ({0}) or client secret ({1}) is invalid", clientId, clientSecret);

                    return;
                }

                this.options.Logger.DebugFormat("Authenticating client '{0}'", clientId);

                var client = await this.options.ClientManager.AuthenticateClientCredentialsAsync(clientId, clientSecret);

                if (!client.Identity.IsAuthenticated)
                {
                    context.SetError("invalid_grant");

                    this.options.Logger.WarnFormat("Client '{0}' was not authenticated because the supplied secret did not match", clientId);

                    return;
                }
            }
            else
            {
                context.SetError("invalid_client");

                this.options.Logger.WarnFormat("Client '{0}' was not authenticated because the provider could not retrieve the client id and client secret from the Authorization header or Form parameters", clientId);

                return;
            }

            context.OwinContext.GetOAuthContext().ClientId = context.ClientId;
            context.OwinContext.GetOAuthContext().RedirectUri = context.Parameters["redirect_uri"];
            context.OwinContext.GetOAuthContext().Scope = context.Parameters["scope"] != null ? context.Parameters["scope"].Split(' ') : null;

            this.options.Logger.DebugFormat("Client '{0}' was successfully authenticated", clientId);

            context.Validated(clientId);
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of any other value. If the application supports custom grant types
        ///             it is entirely responsible for determining if the request should result in an access_token. If context.Validated is called with ticket
        ///             information the response body is produced in the same way as the other standard grant types. If additional response parameters must be
        ///             included they may be added in the final TokenEndpoint call.
        ///             See also http://tools.ietf.org/html/rfc6749#section-4.5
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task GrantCustomExtension(OAuthGrantCustomExtensionContext context)
        {
            if (this.options.Events.UnknownGrantTypeReceived != null)
            {
                this.options.Logger.DebugFormat("Authenticating token request using custom grant type");

                await this.options.Events.UnknownGrantTypeReceived(new UnknownGrantTypeReceivedEventArgs(context));
            }

            await base.GrantCustomExtension(context);
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of "client_credentials". This occurs when a registered client
        ///             application wishes to acquire an "access_token" to interact with protected resources on it's own behalf, rather than on behalf of an authenticated user. 
        ///             If the web application supports the client credentials it may assume the context.ClientId has been validated by the ValidateClientAuthentication call.
        ///             To issue an access token the context.Validated must be called with a new ticket containing the claims about the client application which should be associated
        ///             with the access token. The application should take appropriate measures to ensure that the endpoint isn’t abused by malicious callers.
        ///             The default behavior is to reject this grant type.
        ///             See also http://tools.ietf.org/html/rfc6749#section-4.4.2
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            this.options.Logger.DebugFormat("Authenticating client credentials flow for application '{0}'", context.ClientId);

            if (context.Scope == null || !context.Scope.Any())
            {
                this.options.Logger.WarnFormat("No scope/redirect uri was specified in the request. Request is invalid.");

                context.Rejected();

                return;
            }

            // Store scope in context
            context.OwinContext.GetOAuthContext().Scope = context.Scope;

            // Authenticate client
            var client = await this.options.ClientManager.AuthenticateClientAsync(context.ClientId, context.Scope);

            // Add grant type claim
            client.Identity.RemoveClaim(x => x.Type == ClaimType.GrantType);
            client.Identity.AddClaim(ClaimType.GrantType, GrantType.ClientCredentials);

            if (client.Identity.IsAuthenticated)
            {
                var ticket = new AuthenticationTicket(client.Identity.AsClaimsIdentity(), new AuthenticationProperties());

                context.Validated(ticket);

                this.options.Logger.DebugFormat("Client '{0}' was successfully authenticated", context.ClientId);

                return;
            }

            context.Rejected();

            this.options.Logger.WarnFormat("Client could not be authenticated");
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of "password". This occurs when the user has provided name and password
        /// credentials directly into the client application's user interface, and the client application is using those to acquire an "access_token" and
        /// optional "refresh_token". If the web application supports the
        /// resource owner credentials grant type it must validate the context.Username and context.Password as appropriate. To issue an
        /// access token the context.Validated must be called with a new ticket containing the claims about the resource owner which should be associated
        /// with the access token. The application should take appropriate measures to ensure that the endpoint isn’t abused by malicious callers.
        /// The default behavior is to reject this grant type.
        /// See also http://tools.ietf.org/html/rfc6749#section-4.3.2
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            this.options.Logger.DebugFormat("Authenticating resource owner flow for user '{0}'", Regex.Escape(context.UserName));

            var user = await this.options.UserManager.AuthenticateUserWithPasswordAsync(context.UserName, context.Password);

            if (!user.Identity.IsAuthenticated)
            {
                context.Rejected();

                this.options.Logger.WarnFormat("User '{0}' was not authenticated", Regex.Escape(context.UserName));

                return;
            }

            // Add oauth claims
            user.Identity.AddClaim(ClaimType.Client, context.ClientId);
            user.Identity.RemoveClaim(x => x.Type == ClaimType.GrantType);
            user.Identity.AddClaim(ClaimType.GrantType, GrantType.Password);

            // Activate event if subscribed to
            if (this.options.Events.PrincipalCreated != null)
            {
                var args = new PrincipalCreatedEventArgs(user, context);

                await this.options.Events.PrincipalCreated(args);

                user = new SentinelPrincipal(args.Principal);
            }

            // Convert to proper authentication type
            var principal = this.options.PrincipalProvider.Create(context.Options.AuthenticationType, user.Identity.Claims.ToArray());

            // Validate ticket
            var ticket = new AuthenticationTicket(principal.Identity.AsClaimsIdentity(), new AuthenticationProperties());

            context.Validated(ticket);

            this.options.Logger.DebugFormat("User '{0}' was successfully authenticated", Regex.Escape(context.UserName));
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of "authorization_code". This occurs after the Authorize
        /// endpoint as redirected the user-agent back to the client with a "code" parameter, and the client is exchanging that for an "access_token".
        /// The claims and properties
        /// associated with the authorization code are present in the context.Ticket. The application must call context.Validated to instruct the Authorization
        /// Server middleware to issue an access token based on those claims and properties. The call to context.Validated may be given a different
        /// AuthenticationTicket or ClaimsIdentity in order to control which information flows from authorization code to access token.
        /// The default behavior when using the OAuthAuthorizationServerProvider is to flow information from the authorization code to
        /// the access token unmodified.
        /// See also http://tools.ietf.org/html/rfc6749#section-4.1.3
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task GrantAuthorizationCode(OAuthGrantAuthorizationCodeContext context)
        {
            this.options.Logger.Debug("Authenticating authorization code flow");

            var user = new SentinelPrincipal(context.Ticket.Identity);

            // Add grant type claim
            user.Identity.RemoveClaim(x => x.Type == ClaimType.GrantType);
            user.Identity.AddClaim(ClaimType.GrantType, GrantType.AuthorizationCode);

            context.Validated(user.Identity.AsClaimsIdentity());
        }

        /// <summary>
        /// Called when a request to the Token endpoint arrives with a "grant_type" of "refresh_token". This occurs if your application has issued a "refresh_token" 
        ///             along with the "access_token", and the client is attempting to use the "refresh_token" to acquire a new "access_token", and possibly a new "refresh_token".
        ///             To issue a refresh token the an Options.RefreshTokenProvider must be assigned to create the value which is returned. The claims and properties 
        ///             associated with the refresh token are present in the context.Ticket. The application must call context.Validated to instruct the 
        ///             Authorization Server middleware to issue an access token based on those claims and properties. The call to context.Validated may 
        ///             be given a different AuthenticationTicket or ClaimsIdentity in order to control which information flows from the refresh token to 
        ///             the access token. The default behavior when using the OAuthAuthorizationServerProvider is to flow information from the refresh token to 
        ///             the access token unmodified.
        ///             See also http://tools.ietf.org/html/rfc6749#section-6
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>
        /// Task to enable asynchronous execution
        /// </returns>
        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            this.options.Logger.Debug("Authenticating refresh token flow");

            var user = new SentinelPrincipal(context.Ticket.Identity);

            // Add grant type claim
            user.Identity.RemoveClaim(x => x.Type == ClaimType.GrantType);
            user.Identity.AddClaim(ClaimType.GrantType, GrantType.RefreshToken);

            // Activate event if subscribed to
            if (this.options.Events.PrincipalCreated != null)
            {
                var args = new PrincipalCreatedEventArgs(user, context);

                await this.options.Events.PrincipalCreated(args);

                user = new SentinelPrincipal(args.Principal);
            }

            context.Validated(user.Identity.AsClaimsIdentity());
        }

        /// <summary>Called before the TokenEndpoint redirects its response to the caller.</summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution.</returns>
        public override async Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        {
            if (context.TokenIssued && this.options.Events.TokenIssued != null)
            {
                await this.options.Events.TokenIssued(new TokenIssuedEventArgs(context));
            }

            await base.TokenEndpointResponse(context);
        }

        /// <summary>
        /// Called before the AuthorizationEndpoint redirects its response to the caller. The response could be the
        /// token, when using implicit flow or the AuthorizationEndpoint when using authorization code flow.
        /// An application may implement this call in order to do any final modification of the claims being used
        /// to issue access or refresh tokens. This call may also be used in order to add additional
        /// response parameters to the authorization endpoint's response.
        /// </summary>
        /// <param name="context">The context of the event carries information in and results out.</param>
        /// <returns>Task to enable asynchronous execution</returns>
        public override async Task AuthorizationEndpointResponse(OAuthAuthorizationEndpointResponseContext context)
        {
            await base.AuthorizationEndpointResponse(context);
        }
    }
}