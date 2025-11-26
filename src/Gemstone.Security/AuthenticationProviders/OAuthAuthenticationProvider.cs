//******************************************************************************************************
//  OAuthAuthenticationProvider.cs - Gbtc
//
//  Copyright © 2025, Grid Protection Alliance.  All Rights Reserved.
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
//  07/11/2025 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Gemstone.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Options for the <see cref="OAuthAuthenticationProvider"/> class.
/// </summary>
public class OAuthAuthenticationProviderOptions
{
    /// <summary>
    /// The claimType used to identify the user uniquely.
    /// </summary>
    public string? UserIdClaim { get; set; } = "sub";

    /// <summary>
    /// The Authority to use when making OpenIdConnect calls.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Identifier for the client application.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Secret used to authenticate the client application.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// The space-separated list of permissions to request.
    /// </summary>
    public string Scopes { get; set; } = string.Empty;
}

/// <summary>
/// Provides information about claims available to the OAuth authentication provider.
/// </summary>
/// <param name="options">Options to configure the <see cref="OAuthAuthenticationProvider"/></param>
public partial class OAuthAuthenticationProvider(OAuthAuthenticationProviderOptions options) : IAuthenticationProvider
{
    #region [ Members ]

    // Nested Types
    private class ClaimType(string type, [CallerArgumentExpression(nameof(type))] string? alias = null) : IClaimType
    {
        public string Type { get; } = type;
        public string Alias { get; } = alias ?? string.Empty;
        public string Description { get; } = string.Empty;
    }

    private class ProviderClaim(string value, string description) : IProviderClaim
    {
        /// <summary>Group SID</summary>
        public string Value => value;

        /// <summary>FQDN (group@domain.com)</summary>
        public string Description => description;

        /// <summary>Empty</summary>
        public string LongDescription => string.Empty;
    }

    #endregion

    #region [ Constructors ]

    /// <summary>
    /// Creates a new instance of the <see cref="OAuthAuthenticationProvider"/> class.
    /// </summary>
    public OAuthAuthenticationProvider()
        : this(new())
    {
    }

    #endregion

    #region [ Properties ]

    private OAuthAuthenticationProviderOptions Options { get; } = options;

    #endregion

    #region [ Methods ]

    /// <inheritdoc/>
    public string GetIdentity(ClaimsPrincipal principal)
    {
        if (ClaimTypes.Length == 1)
            ClaimTypes = principal
                .Claims
                .Select(claim => claim.Type)
                .Distinct()
                .Select(type => new ClaimType(type)).Prepend(new ClaimType("Gemstone.AllUsers")).ToArray();

        string? identity = principal
            .FindFirst(Options.UserIdClaim ?? "sub")?
            .Value;

        identity ??= principal.Identity?.Name;
        return identity ?? string.Empty;
    }

    /// <inheritdoc/>
    public IEnumerable<IClaimType> GetClaimTypes()
    {
        return ClaimTypes;
    }

    /// <inheritdoc/>
    public IEnumerable<IProviderClaim> FindClaims(string claimType, string searchText)
    {
        yield return new ProviderClaim(searchText, searchText);
    }

    #endregion

    #region [ Static ]

    // Static Properties
    private static ClaimType[] ClaimTypes
    {
        get;
        set;
    } = [new ClaimType("Gemstone.AllUsers")];

    // Static Methods
    private static string Escape(string ldapValue)
    {
        Regex pattern = SpecialCharacterPattern();

        return pattern.Replace(ldapValue, match => match.Value switch
        {
            @"\*" => @"\2A",
            "(" => @"\28",
            ")" => @"\29",
            @"\\" => @"\5C",
            "\0" => @"\00",

            // Character escaped with backslash
            string v => v[1..]
        });
    }

    [GeneratedRegex(@"\\.|[()\0]")]
    private static partial Regex SpecialCharacterPattern();

    /// <summary>
    /// Defines the settings used to configure the <see cref="OAuthAuthenticationProvider"/> in the Configuration File.
    /// </summary>
    /// <param name="settings"></param>
    public static void DefineSettings(Settings settings)
    {
        dynamic section = settings["Security.OpenIDConnect"];

        section.Scopes = ("profile", "Defines the scopes requested from the OpenID Connect provider in a comma sepperated list.");
        section.ClientId = ("ClientID", "Defines the client ID of the application.");
        section.ClientSecret = ("ClientSecret", "Defines the secret used to autheticate the client with the OpenID Connect provider.");
        section.Authority = ("https://auth.gridprotectionalliance.org/realms/Test", "Defines the authority URL of the OpenID Connect provider.");
        section.UserIdClaim = ("sub", "Defines the claim used to identify the user.");
        section.Enabled = (false, "Defines a flag to enable the OAuth authentication provider.");

    }
    #endregion
}

/// <summary>
/// Defines extensions for setting up the <see cref="OAuthAuthenticationProvider"/>.
/// </summary>
public static class OAuthAuthenticationProviderExtensions
{
    /// <summary>
    /// The identity used by default if one is not provided.
    /// </summary>
    public const string DefaultIdentity = "oauth";

    /// <summary>
    /// Adds the OAuth authentication provider as a singleton service using the default identity and options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddOAuthAuthenticationProvider(this IServiceCollection services)
    {
        return services.AddOAuthAuthenticationProvider(DefaultIdentity);
    }

    /// <summary>
    /// Adds the OAuth authentication provider as a singleton service using the default identity and given options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="options">The options used to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddOAuthAuthenticationProvider(this IServiceCollection services, OAuthAuthenticationProviderOptions options)
    {
        return services.AddOAuthAuthenticationProvider(DefaultIdentity, options);
    }

    /// <summary>
    /// Adds the OAuth authentication provider as a transient service using the default identity and configured options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="configure">Method invoked to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddOAuthAuthenticationProvider(this IServiceCollection services, Action<OAuthAuthenticationProviderOptions> configure)
    {
        return services.AddOAuthAuthenticationProvider(DefaultIdentity, configure);
    }

    /// <summary>
    /// Adds the OAuth authentication provider as a singleton service using the given identity and default options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddOAuthAuthenticationProvider(this IServiceCollection services, string identity)
    {
        return services.AddAuthenticationProvider<OAuthAuthenticationProvider>(identity);
    }

    /// <summary>
    /// Adds the OAuth authentication provider as a singleton service using the given identity and options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <param name="options">The options used to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddOAuthAuthenticationProvider(this IServiceCollection services, string identity, OAuthAuthenticationProviderOptions options)
    {
        OAuthAuthenticationProvider provider = new(options);
        return services.AddAuthenticationProvider(identity, provider);
    }

    /// <summary>
    /// Adds the OAuth authentication provider as a transient service using the given identity and configured options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <param name="configure">Method invoked to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddOAuthAuthenticationProvider(this IServiceCollection services, string identity, Action<OAuthAuthenticationProviderOptions> configure)
    {
        return services.AddKeyedTransient<IAuthenticationProvider>(identity, (_, _) =>
        {
            OAuthAuthenticationProviderOptions options = new();
            configure(options);
            return new OAuthAuthenticationProvider(options);
        });
    }
}
