# Sentinel.OAuth
An OAuth server based on the ASP.NET OWIN OAuth 2.0 Authorization Server.
This project aims to simplify the work with setting up OAuth on a WebAPI application, by providing you with simpler interfaces and less work to do before  you have proper authorization up and running.

## Features
- Simple setup
- Supports authorization codes and refresh tokens out of the box
- Easy to extend and configure

## Setting up
### The easy way
In its simplest form `Sentinel` only requires the following line in your OWIN Startup class to work:

```csharp
app.UseSentinelAuthorizationServer(
    new SentinelAuthorizationServerOptions()
       {
           ClientManager = new SimpleClientManager(),
           UserManager = new SimpleUserManager()
       });
...

public class SimpleUserManager : IUserManager 
{
    public async Task<ClaimsPrincipal> AuthenticateUserWithPasswordAsync(string username, string password)
    {
        // Return an authenticated principal if the username matches the password
        if (username == password)
        {
            return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, username) }, AuthenticationType.OAuth));
        }

        return new ClaimsPrincipal(new ClaimsIdentity());
    }
}

public class SimpleClientManager : IClientManager 
{
    public async Task<ClaimsPrincipal> AuthenticateClientIdAsync(string clientId, string redirectUri)
    {
        // Just return an authenticated principal with the client id as name (allows all clients)
        return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, clientId) }, AuthenticationType.OAuth));
    }

    public async Task<ClaimsPrincipal> AuthenticateClientCredentialsAsync(string clientId, string clientSecret)
    {
        // Return an authenticated principal if the client secret matches the client id
        if (clientId == clientSecret)
        {
            return new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>() { new Claim(ClaimTypes.Name, clientId) }, AuthenticationType.OAuth));
        }

        return new ClaimsPrincipal(new ClaimsIdentity());
    }
}
```
    
This will set up the OAuth server with the default settings, which are as follows:

| Setting | Default Value |
| --- | --- |
| Access Token Lifetime | 1 hour |
| Authorization Code Lifetime | 5 minutes |
| Refresh Token Lifetime | 3 months (90 days) |
| Token Endpoint | `/oauth/token` |
| Authorization Code Endpoint | `/oauth/authorize` |
| Token Format | `Sentinel` A `PBKDF2` hasher with 256-bit key length |

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

## Extending
Did I mention that `Sentinel` is extendable? :-)

### Custom OAuth Grant Types
TODO: Example where using custom grant type to 

### Custom User Manager
TODO: Example where using ASP.NET Identity

### Custom Client Manager
TODO: Example where using ASP.NET Identity

### Customer Token Manager
TODO: Example where using Redis for storing tokens

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
- Add support for JWT tokens
- Add support and example on how to use Google, Microsoft, Facebook, Twitter accounts with Sentinel
- Add support for two-factor authentication
- Add support for scope handling
