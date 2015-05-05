# Sentinel
[![TeamCity Build Status](https://img.shields.io/teamcity/https/teamcity.knowit.no/e/External_Sentinel_General_Release.svg?style=flat-square)](https://teamcity.knowit.no/viewType.html?buildTypeId=External_Sentinel_General_Release&tab=buildTypeStatusDiv&branch_External_Sentinel_General=__all_branches__)  

[![NuGet Downloads](https://img.shields.io/nuget/dt/Sentinel.OAuth.Core.svg?style=flat-square&label=Sentinel.OAuth.Core downloads)](https://www.nuget.org/packages/Sentinel.OAuth.Core) [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.Core.svg?style=flat-square&label=Sentinel.OAuth.Core version)](https://www.nuget.org/packages/Sentinel.OAuth.Core)  
[![NuGet Downloads](https://img.shields.io/nuget/dt/Sentinel.OAuth.svg?style=flat-square&label=Sentinel.OAuth downloads)](https://www.nuget.org/packages/Sentinel.OAuth) [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.svg?style=flat-square&label=Sentinel.OAuth version)](https://www.nuget.org/packages/Sentinel.OAuth)  
[![NuGet Downloads](https://img.shields.io/nuget/dt/Sentinel.OAuth.Client.svg?style=flat-square&label=Sentinel.OAuth.Client downloads)](https://www.nuget.org/packages/Sentinel.OAuth.Client) [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.Client.svg?style=flat-square&label=Sentinel.OAuth.Client version)](https://www.nuget.org/packages/Sentinel.OAuth.Client)  

`Sentinel` is an OAuth server based on the ASP.NET OWIN OAuth 2.0 Authorization Server.
This project aims to simplify the work with setting up OAuth on a WebAPI application, by providing you with simpler interfaces and less work to do before  you have proper authorization up and running.

## Features
- Simple setup
- Supports authorization codes and refresh tokens out of the box
- Easy to extend and configure

## Setting up
### The easy way
In its simplest form `Sentinel` only requires the following code in your OWIN Startup class to work:

```csharp
app.UseSentinelAuthorizationServer(
    new SentinelAuthorizationServerOptions()
       {
           ClientManager = new SimpleClientManager(),
           UserManager = new SimpleUserManager()
       });
```
In addition, you need to implement a `IUserManager` and a `IClientManager` for validating users and clients:

```csharp
public class SimpleUserManager : IUserManager
{
    /// <summary>Authenticates the user using username and password.</summary>
    /// <param name="username">The username.</param>
    /// <param name="password">The password.</param>
    /// <returns>The client principal.</returns>
    public async Task<ISentinelPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
    {
        // Just return an authenticated principal with the username as name if the username matches the password
        if (username == password)
        {
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, username)));
        }

        return SentinelPrincipal.Anonymous;
    }
}

public class SimpleClientManager : IClientManager 
{
    /// <summary>
    ///     Authenticates the client. Used when authenticating with the authorization_code grant type.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <param name="redirectUri">The redirect URI.</param>
    /// <returns>The client principal.</returns>
    public async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, string redirectUri)
    {
        // Just return an authenticated principal with the client id as name (allows all clients)
        return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, clientId)));
    }

    /// <summary>
    ///     Authenticates the client. Used when authenticating with the client_credentials grant type.
    /// </summary>
    /// <param name="clientId">The client id.</param>
    /// <param name="scope">The redirect URI.</param>
    /// <returns>The client principal.</returns>
    public async Task<ISentinelPrincipal> AuthenticateClientAsync(string clientId, IEnumerable<string> scope)
    {
        // Just return an authenticated principal with the client id as name (allows all clients)
        return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, clientId)));
    }

    /// <summary>Authenticates the client credentials using client id and secret.</summary>
    /// <param name="clientId">The client id.</param>
    /// <param name="clientSecret">The client secret.</param>
    /// <returns>The client principal.</returns>
    public async Task<ISentinelPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret)
    {
        // Return an authenticated principal if the client secret matches the client id
        if (clientId == clientSecret)
        {
            return new SentinelPrincipal(new SentinelIdentity(AuthenticationType.OAuth, new SentinelClaim(ClaimTypes.Name, clientId)));
        }

        return SentinelPrincipal.Anonymous;
    }
}
```
You might have noticed the use if `ISentinelPrincipal`, `ISentinelIdentity` and `SentinelClaim`.  
- `ISentinelPrincipal` is a extension of `IPrincipal`, the base interface for principals in the .NET world. `ClaimsPrincipal` also implements this interface, and the two are convertible via the included extension methods, or in the constructor of `ISentinelPrincipal`. 
- `ISentinelIdentity` is a extension of `IIdentity`, the base interface for principals in the .NET world. `ClaimsIdentity` also implements this interface, and the two are convertible via the included extension methods, or in the constructor of `ISentinelIdentity`. 
- `SentinelClaim` and its interface `ISentinelClaim` do not derive from the `System.IdentityModel.Claims.Claim`. Instead it can take in a `Claim` in its constructor and can convert back implicitly.

The reason for these custom types are that the built-in `ClaimsPrincipal` is not PCL-compatible, and the `Core` and `Client` packages must be PCL-compatible. I've included a lot of conversion options, so it should not pose a problem for you.

The above setup will configure the OAuth server with the default settings, which are as follows:

| Setting | Default Value |
| --- | --- |
| Access Token Lifetime | 1 hour |
| Authorization Code Lifetime | 5 minutes |
| Refresh Token Lifetime | 3 months (90 days) |
| Token Endpoint | `/oauth/token` |
| Authorization Code Endpoint | `/oauth/authorize` |
| Token Format | `Sentinel` (A `PBKDF2` hasher with 256-bit key length) |

### The advanced way
The easy way is not always the best way, and `Sentinel` supports customization of user and client management, as well as custom token stores.

Here is an example on how to use a custom user manager, client manager and user store:

```csharp
app.UseSentinelAuthorizationServer(
    new SentinelAuthorizationServerOptions()
        {
            AccessTokenLifetime = TimeSpan.FromHours(1),
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(5),
            RefreshTokenLifetime = TimeSpan.FromDays(180),
            UserManager = new SimpleUserManager(),
            ClientManager = new SimpleClientManager(),
            TokenManager = new SimpleTokenManager()
        });
```
## Usage
There is nothing special with `Sentinel` as an OAuth 2 provider, you can use a normal OAuth client that conforms to the [specification](https://tools.ietf.org/html/rfc6749).  
`Sentinel` also includes a [client for use in .NET projects](https://www.nuget.org/packages/Sentinel.OAuth.Client/) ([source](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.Client))

**There is one thing that must be mentioned however**. `Sentinel` requires the client redirect uri parameter to be present on the `authorize` request. Not all OAuth 2 providers do this, but it is possible [according to the specification](https://tools.ietf.org/html/rfc6749#section-4.1.1).

## Extending
Did I mention that `Sentinel` is extendable? :-)

### Custom OAuth Grant Types
TODO: Example using custom grant type to add a new property to the token response

### Custom User Manager
TODO: Example using ASP.NET Identity for storing and validating users

### Custom Client Manager
TODO: Example using RavenDB for storing and validating clients

### Customer Token Manager
TODO: Example using Redis for storing tokens

## Claims
There are some claims that will be added to your user principal that are specific for `Sentinel`.  
Below you can find an overview of claims with explanations.

| Claim | Explanation |
| --- | --- |
| `urn:oauth:client` | The client that was used to authenticate the user |
| `urn:oauth:scope` | The scope that was set when asking for an authorization code |
| `urn:oauth:accesstoken` | The access token for the current user object |
| `urn:oauth:refreshtoken` | The refresh token for the current user object |

## TODO
- Add support for custom grant types
- Add support for other token formats (I.e. JWT and the host defaults)
- Add support and example on how to use Google, Microsoft, Facebook, Twitter accounts with Sentinel
- Add support for two-factor authentication
- Add support for scope handling
