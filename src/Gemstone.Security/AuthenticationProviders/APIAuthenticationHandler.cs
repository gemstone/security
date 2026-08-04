//******************************************************************************************************
//  APIAuthenticationHandler.cs - Gbtc
//
//  Copyright © 2026, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the MIT License (MIT), the "License"; you may not use this
//  file except in compliance with the License. You may obtain a copy of the License at:
//
//      http://opensource.org/licenses/MIT
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  07/09/2026 - C. Lackner
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Options for the <see cref="APIAuthenticationHandler"/> class.
/// </summary>
public class APIAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Function that parses and validates an API token.
    /// </summary>
    public Func<string, APIToken?>? ValidateToken { get; set; }
}

/// <summary>
/// Represents metadata associated with an API token.
/// </summary>
public class APIToken
{
    /// <summary>
    /// Gets or sets the name of the API user.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the time at which the token expires.
    /// </summary>
    public DateTime Expiration { get; set; }

    /// <summary>
    /// Gets or sets the list of claims assigned to the API user.
    /// </summary>
    public Claim[] Claims { get; set; } = [];
}

/// <summary>
/// Represents an authentication handler for API users.
/// </summary>
public class APIAuthenticationHandler(IOptionsMonitor<APIAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<APIAuthenticationOptions>(options, logger, encoder)
{
    /// <summary>
    /// Authentication type used for API authentication.
    /// </summary>
    public const string AuthenticationType = "APIAuthentication";

    private const string HttpAuthenticationScheme = "Bearer";

    private string AuthorizationHeader => Request.Headers.Authorization.ToString();

    /// <summary>
    /// Parses the Authorization header and API token.
    /// </summary>
    /// <returns>The result of authentication.</returns>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        AuthenticateResult result = Authenticate();
        return Task.FromResult(result);
    }

    /// <summary>
    /// Returns a 401 Unauthorized response with the WWW-Authenticate header.
    /// </summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = HttpAuthenticationScheme;
        return base.HandleChallengeAsync(properties);
    }

    private AuthenticateResult Authenticate()
    {
        string prefix = $"{HttpAuthenticationScheme} ";

        if (!AuthorizationHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        string token = AuthorizationHeader[prefix.Length..].Trim();
        APIToken? resolvedToken;

        try
        {
            resolvedToken = Options.ValidateToken?.Invoke(token);
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail(ex);
        }

        if (resolvedToken is null)
            return AuthenticateResult.NoResult();

        if (resolvedToken.Expiration < DateTime.UtcNow)
            return AuthenticateResult.Fail("Token expired");

        ClaimsIdentity identity = new(AuthenticationType);
        identity.AddClaim(new(ClaimTypes.Name, resolvedToken.Name, Options.ClaimsIssuer));
        identity.AddClaims(resolvedToken.Claims);

        ClaimsPrincipal principal = new(identity);
        AuthenticationTicket ticket = new(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }
}

/// <summary>
/// Extension methods for <see cref="APIAuthenticationHandler"/>.
/// </summary>
public static class APIAuthenticationHandlerExtensions
{
    /// <summary>
    /// Adds the API authentication handler to the application.
    /// </summary>
    /// <param name="builder">The builder used to configure authentication</param>
    /// <returns>The builder used to configure authentication.</returns>
    public static AuthenticationBuilder AddAPIAuthentication(this AuthenticationBuilder builder)
    {
        return builder.AddAPIAuthentication(options => { });
    }

    /// <summary>
    /// Adds the API authentication handler to the application.
    /// </summary>
    /// <param name="builder">The builder used to configure authentication</param>
    /// <param name="configureOptions">Action to configure the <see cref="APIAuthenticationOptions"/></param>
    /// <returns>The builder used to configure authentication.</returns>
    public static AuthenticationBuilder AddAPIAuthentication(this AuthenticationBuilder builder, Action<APIAuthenticationOptions> configureOptions)
    {
        return builder.AddAPIAuthentication("api", configureOptions);
    }

    /// <summary>
    /// Adds the API authentication handler to the application.
    /// </summary>
    /// <param name="builder">The builder used to configure authentication</param>
    /// <param name="authenticationScheme">The name of the scheme</param>
    /// <param name="configureOptions">Action to configure the <see cref="APIAuthenticationOptions"/></param>
    /// <returns>The builder used to configure authentication.</returns>
    public static AuthenticationBuilder AddAPIAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<APIAuthenticationOptions> configureOptions)
    {
        return builder.AddAPIAuthentication(authenticationScheme, null, configureOptions);
    }

    /// <summary>
    /// Adds the API authentication handler to the application.
    /// </summary>
    /// <param name="builder">The builder used to configure authentication</param>
    /// <param name="authenticationScheme">The name of the scheme</param>
    /// <param name="displayName">The display name of the scheme</param>
    /// <param name="configureOptions">Action to configure the <see cref="APIAuthenticationOptions"/></param>
    /// <returns>The builder used to configure authentication.</returns>
    public static AuthenticationBuilder AddAPIAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<APIAuthenticationOptions> configureOptions)
    {
        return builder.AddScheme<APIAuthenticationOptions, APIAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}
