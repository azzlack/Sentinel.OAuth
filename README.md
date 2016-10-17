# Sentinel
[![TeamCity Build Status](https://img.shields.io/teamcity/https/teamcity.knowit.no/e/External_Sentinel_General_Release.svg?style=flat-square)](https://teamcity.knowit.no/viewType.html?buildTypeId=External_Sentinel_General_Release&tab=buildTypeStatusDiv&branch_External_Sentinel_General=__all_branches__)  

`Sentinel` is an OAuth server based on the ASP.NET OWIN OAuth 2.0 Authorization Server.
This project aims to simplify the work with setting up OAuth on a WebAPI application, by providing you with simpler interfaces and less work to do before  you have proper authorization up and running.

| Package | Description | Version |
| --- | --- | --- |
| `Sentinel.OAuth.Core` | <sub><sup>The base package that is used by all the other packages and 3rd party plugins</sup></sub> | [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.Core.svg?style=flat-square)](https://www.nuget.org/packages/Sentinel.OAuth.Core) |
| `Sentinel.OAuth` | <sub><sup>The authorization provider itself</sup></sub> | [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.svg?style=flat-square)](https://www.nuget.org/packages/Sentinel.OAuth) |
| `Sentinel.OAuth.Client` | <sub><sup>A generic OAuth client built on the [Microsoft HTTP Client Libraries](https://www.nuget.org/packages/Microsoft.Net.Http/)</sup></sub> | [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.Client.svg?style=flat-square)](https://www.nuget.org/packages/Sentinel.OAuth.Client) |
| `Sentinel.OAuth.TokenManagers.Redis` | <sub><sup>A token manager using [Redis](http://redis.io/) for storage</sup></sub> | [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.TokenManagers.Redis.svg?style=flat-square)](https://www.nuget.org/packages/Sentinel.OAuth.TokenManagers.Redis) |
| `Sentinel.OAuth.TokenManagers.RavenDB` | <sub><sup>A token manager using [RavenDB](http://ravendb.net/) for storage</sup></sub> | [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.TokenManagers.RavenDB.svg?style=flat-square)](https://www.nuget.org/packages/Sentinel.OAuth.TokenManagers.RavenDB) |
| `Sentinel.OAuth.TokenManagers.SQL` | <sub><sup>A token manager using `SQL` for storage</sup></sub> | [![NuGet Version](https://img.shields.io/nuget/v/Sentinel.OAuth.TokenManagers.SQL.svg?style=flat-square)](https://www.nuget.org/packages/Sentinel.OAuth.TokenManagers.SQL) |

## Features
- Simple setup
- Supports authorization codes and refresh tokens out of the box
- Easy to extend and configure

## Contributing
To make contributions to this project, please fork the `develop` branch and make your pull request against the `develop` branch.

## Setting up
### The easy way
Sentinel needs to know where and how your users and clients are located. This is accomplished by making an implementation of the `IUserRepository` and `IClientRepository` interfaces. These have methods that is responsible for locating users and clients, stuff that is probable very specific to your application.  

In its simplest form `Sentinel` the only requires the following code in your OWIN Startup class to work:

```csharp
app.UseSentinelAuthorizationServer(
    new SentinelAuthorizationServerOptions()
       {
           IssuerUri = new Uri("http://my.host"),
           ClientRepository = new SimpleClientRepository(),
           UserRepository = new SimpleUserRepository()
       });
```
The `IUserRepository` and a `IClientRepository` can be implemented like this.  

```csharp
public class SimpleUserRepository : IUserRepository
{
    /// <summary>Gets the users.</summary>
    /// <returns>The users.</returns>
    public async Task<IEnumerable<IUser>> GetUsers()
    {
        return new List<IUser>() 
            {
                new User() { UserId = "myid", Password = "some-hash" }
            };
    }

    /// <summary>Gets a user.</summary>
    /// <param name="userId">Identifier for the user.</param>
    /// <returns>The user.</returns>
    public async Task<IUser> GetUser(string userId)
    {
        return new User() { UserId = userId, Password = "some-hash" };
    }
}

public class SimpleClientRepository : IClientRepository
{
    /// <summary>Gets the clients in this collection.</summary>
    /// <returns>An enumerator that allows foreach to be used to process the clients in this collection.</returns>
    public async Task<IEnumerable<IClient>> GetClients()
    {
        return new List<IClient>() 
            {
                new Client() { ClientId = clientId, ClientSecret = "some-hash", RedirectUri = "http://localhost" }
            };
    }
    
    /// <summary>Gets the client with the specified id.</summary>
    /// <param name="clientId">Identifier for the client.</param>
    /// <returns>The client.</returns>
    public async Task<IClient> GetClient(string clientId)
    {
        return new Client() { ClientId = clientId, ClientSecret = "some-hash", RedirectUri = "http://localhost" };
    }
}
```

### Hashing and validation
By default, Sentinel uses `HMACSHA-256` for token hashing, and `PBKDF2` for password/client secret hashing and validation.  
If you use (or want to use) something other than this, you need to swap out the `UserManager` and `ClientManager` properties on the configuration object.

### Conclusion
The above setup will configure the OAuth server with the default settings, which are as follows:

| Setting | Default Value |
| --- | --- |
| Access Token Lifetime | 1 hour |
| Authorization Code Lifetime | 5 minutes |
| Refresh Token Lifetime | 3 months (90 days) |
| Token Endpoint | `/oauth/token` |
| Authorization Code Endpoint | `/oauth/authorize` |
| UserInfo Endpoint | `/openid/identity` |
| Token Format | `JWT` (Using a `SHA-512` hashing algorithm to encrypt the token) |

### Notes
You might have noticed the use if `ISentinelPrincipal`, `ISentinelIdentity` and `SentinelClaim`.  
- `ISentinelPrincipal` is a extension of `IPrincipal`, the base interface for principals in the .NET world. `ClaimsPrincipal` also implements this interface, and the two are convertible via the included extension methods, or in the constructor of `ISentinelPrincipal`.
- `ISentinelIdentity` is a extension of `IIdentity`, the base interface for principals in the .NET world. `ClaimsIdentity` also implements this interface, and the two are convertible via the included extension methods, or in the constructor of `ISentinelIdentity`.
- `SentinelClaim` and its interface `ISentinelClaim` do not derive from the `System.IdentityModel.Claims.Claim`. Instead it can take in a `Claim` in its constructor and can convert back implicitly.

The reason for these custom types are that the built-in `ClaimsPrincipal` is not PCL-compatible, and the `Core` and `Client` packages must be PCL-compatible. I've included a lot of conversion options, so it should not pose a problem for you.

## On supporting the `authorization_code` flow
`Sentinel` does not include a view for your users to log in when using the `/oauth/authorize` endpoint.
You need to create a page/controller that responds to that endpoint, and that logs in the user using the OWIN AuthorizationManager.
However, the [Sentinel.OAuth.Authorize](https://www.nuget.org/packages/Sentinel.OAuth.AuthorizationCode) package includes a `BaseOAuthController` class, and it is fairly easy to use:

```csharp
Coming soon
```

## Usage
There is nothing special with `Sentinel` as an OAuth 2 provider, you can use a normal OAuth client that conforms to the [specification](https://tools.ietf.org/html/rfc6749).  
`Sentinel` also includes a [client for use in .NET projects](https://www.nuget.org/packages/Sentinel.OAuth.Client/) ([source](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.Client))

**There is one thing that must be mentioned however**. `Sentinel` requires the client redirect uri parameter to be present on the `authorize` request. Not all OAuth 2 providers do this, but it is recommended [according to the specification](https://tools.ietf.org/html/rfc6749#section-3.1.2.2).

## Performance
These are the average performance results for the included storage providers in the current version.  
Please note that these tests may not be fair. The tests are equal, but the connection is not. In addition, I currently do not have a lot of [statistics history](https://teamcity.knowit.no/viewType.html?buildTypeId=External_Sentinel_SentinelOAuth_Develop&tab=buildTypeStatistics&branch_External_Sentinel_General=__all_branches__) so the averages might be off by quite a lot.

Also, you must not discard the idea that some methods need to be optimized :-)  
The Authenticate methods for the Redis provider are too slow and should be made much faster.

| Action                          | Memory | SQL (LocalDb) | Redis  | RavenDB |
| --- | ---: | ---: | ---: | ---: |
| Create Authorization Code       | 442ms  | 21ms          | 477ms  | 488ms |
| Authenticate Authorization Code | 445ms  | 24ms          | 702ms  | 594ms |
| Create Access Token             | 451ms  | 23ms          | 486ms  | 468ms |
| Authenticate Access Token       | 464ms  | 60ms          | 6244ms | 1004ms |
| Create Refresh Token            | 433ms  | 4ms           | 472ms  | 447ms |
| Authenticate Refresh Token      | 460ms  | 47ms          | 3424ms | 613ms |

## Extending
The samples below can be mixed and matched to your liking. You can use `SQL Server` for storing users and clients, and then use `RavenDB` for storing tokens, or the other way around :-)

### Custom OAuth Grant Types
TODO: Example using custom grant type to add a new property to the token response

### Custom User Manager
It is possible to use the `ASP.NET Identity` system to store your users and use `Sentinel` at the same time.  
Please look at the sample implementation in the [AspNetIdentityUserManager project](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.UserManagers.AspNetIdentityUserManager)  

There is also a demo using `Dapper` and a vanilla SQL database in the [SqlServerUserManager project](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.UserManagers.SqlServerUserManager).

### Custom Client Manager
There is a sample implementation using `Dapper` and SQL Server [here](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.ClientManagers.SqlServerClientManager).
You can also use `NoSQL` databases for storing clients.

### Custom Token Manager
Guides on how to use token managers with persistent storage.

- TODO: [Using `Dapper` and `SQL Server`](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.TokenManagers.SqlServerTokenRepository)
- TODO: [Using `RavenDb`](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.TokenManagers.RavenDbTokenRepository)
- TODO: [Using `Redis`](https://github.com/azzlack/Sentinel.OAuth/tree/develop/src/Sentinel.OAuth.TokenManagers.RedisTokenRepository)

## Claims
There are some claims that will be added to your user principal that are specific for `Sentinel`.  
Below you can find an overview of claims with explanations.

| Claim | Explanation |
| --- | --- |
| `urn:oauth:client` | The client that was used to authenticate the user |
| `urn:oauth:scope` | The scope that was set when asking for an authorization code or access token |
| `urn:oauth:accesstoken` | The access token for the current user object |
| `urn:oauth:refreshtoken` | The refresh token for the current user object |

## TODO (Roadmap)
- Add support and example on how to use Google, Microsoft, Facebook, Twitter accounts with Sentinel
- Add support for two-factor authentication
- Add support for scope handling
