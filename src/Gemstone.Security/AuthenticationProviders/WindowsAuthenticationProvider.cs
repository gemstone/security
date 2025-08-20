//******************************************************************************************************
//  WindowsAuthenticationProvider.cs - Gbtc
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
using System.DirectoryServices;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Options for the <see cref="WindowsAuthenticationProvider"/> class.
/// </summary>
public class WindowsAuthenticationProviderOptions
{
    /// <summary>
    /// Root path from which LDAP searches should be performed.
    /// </summary>
    public string? LDAPPath { get; set; }
}

/// <summary>
/// Provides information about claims available to the Windows authentication provider.
/// </summary>
/// <param name="options">Options to configure the <see cref="WindowsAuthenticationProvider"/></param>
public partial class WindowsAuthenticationProvider(WindowsAuthenticationProviderOptions options) : IAuthenticationProvider
{
    #region [ Members ]

    // Nested Types
    private enum ObjectClass { User, Group }

    private class UserAccount(string identity, string accountName, string? firstName, string? lastName) : IUserAccount
    {
        /// <summary>User SID</summary>
        public string Identity => identity;

        /// <summary>User principal name</summary>
        public string AccountName => accountName;

        /// <summary>Given name</summary>
        public string? FirstName => firstName;

        /// <summary>Surname</summary>
        public string? LastName => lastName;
    }

    private class GroupSID : IClaimType
    {
        public string Type { get; } = System.Security.Claims.ClaimTypes.GroupSid;
        public string Alias { get; } = nameof(System.Security.Claims.ClaimTypes.GroupSid);
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

    // Constants
    private const string IdentityClaim = System.Security.Claims.ClaimTypes.PrimarySid;

    #endregion

    #region [ Constructors ]

    /// <summary>
    /// Creates a new instance of the <see cref="WindowsAuthenticationProvider"/> class.
    /// </summary>
    public WindowsAuthenticationProvider()
        : this(new())
    {
    }

    #endregion

    #region [ Properties ]

    private WindowsAuthenticationProviderOptions Options { get; } = options;

    #endregion

    #region [ Methods ]

    /// <inheritdoc/>
    public string GetIdentity(ClaimsPrincipal principal)
    {
        string? identity = principal
            .FindFirst(IdentityClaim)?
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
    public IEnumerable<IUserAccount> FindUsers(string searchText)
    {
        if (!OperatingSystem.IsWindows())
            yield break;

        string escapedSearchText = Escape(searchText);

        using DirectorySearcher searcher = new(Options.LDAPPath)
        {
            Filter = $"(&(objectCategory=user)(userPrincipalName={escapedSearchText}))"
        };

        using SearchResultCollection results = searcher.FindAll();

        foreach (SearchResult result in results)
        {
            using DirectoryEntry entry = result.GetDirectoryEntry();
            object? objectSid = entry.InvokeGet("objectSid");
            object? userPrincipalName = entry.InvokeGet("userPrincipalName");
            object? givenName = entry.InvokeGet("givenName");
            object? sn = entry.InvokeGet("sn");

            if (objectSid is not byte[] sidBuffer)
                continue;

            if (userPrincipalName is null)
                continue;

            SecurityIdentifier sid = new(sidBuffer, 0);
            string identity = $"{sid}";
            string accountName = $"{userPrincipalName}";
            string firstName = $"{givenName}";
            string lastName = $"{sn}";
            yield return new UserAccount(identity, accountName, firstName, lastName);
        }
    }

    /// <inheritdoc/>
    public IEnumerable<IProviderClaim> FindClaims(string claimType, string searchText)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(claimType, GroupClaimType.Type);

        if (!OperatingSystem.IsWindows())
            yield break;

        string escapedSearchText = Escape(searchText);

        using DirectorySearcher searcher = new(Options.LDAPPath)
        {
            Filter = $"(&(objectCategory=group)(sAMAccountName={escapedSearchText}))"
        };

        using SearchResultCollection results = searcher.FindAll();

        foreach (SearchResult result in results)
        {
            using DirectoryEntry entry = result.GetDirectoryEntry();
            object? objectSid = entry.InvokeGet("objectSid");
            object? sAMAccountName = entry.InvokeGet("sAMAccountName");
            object? distinguishedName = entry.InvokeGet("distinguishedName");

            if (objectSid is not byte[] sidBuffer)
                continue;

            SecurityIdentifier sid = new(sidBuffer, 0);
            string? domain = parse($"{distinguishedName}");
            string value = $"{sid}";
            string description = (domain is not null) ? $"{sAMAccountName}@{domain}" : $"{sAMAccountName}";
            yield return new ProviderClaim(value, description);
        }

        static string? parse(string dn)
        {
            if (dn.Length == 0)
                return null;

            IEnumerable<string> dc = dn
                .Split(',')
                .SkipWhile(n => !n.StartsWith("DC="))
                .TakeWhile(n => n.StartsWith("DC="))
                .Select(n => n[3..]);

            return string.Join('.', dc);
        }
    }

    #endregion

    #region [ Static ]

    // Static Properties
    private static GroupSID GroupClaimType { get; } = new();
    private static GroupSID[] ClaimTypes { get; } = [GroupClaimType];

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

    #endregion
}

/// <summary>
/// Defines extensions for setting up the <see cref="WindowsAuthenticationProvider"/>.
/// </summary>
public static class WindowsAuthenticationProviderExtensions
{
    /// <summary>
    /// The identity used by default if one is not provided.
    /// </summary>
    public const string DefaultIdentity = "windows";

    /// <summary>
    /// Adds the windows authentication provider as a singleton service using the default identity and options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddWindowsAuthenticationProvider(this IServiceCollection services)
    {
        return services.AddWindowsAuthenticationProvider(DefaultIdentity);
    }

    /// <summary>
    /// Adds the windows authentication provider as a singleton service using the default identity and given options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="options">The options used to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddWindowsAuthenticationProvider(this IServiceCollection services, WindowsAuthenticationProviderOptions options)
    {
        return services.AddWindowsAuthenticationProvider(DefaultIdentity, options);
    }

    /// <summary>
    /// Adds the windows authentication provider as a transient service using the default identity and configured options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="configure">Method invoked to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddWindowsAuthenticationProvider(this IServiceCollection services, Action<WindowsAuthenticationProviderOptions> configure)
    {
        return services.AddWindowsAuthenticationProvider(DefaultIdentity, configure);
    }

    /// <summary>
    /// Adds the windows authentication provider as a singleton service using the given identity and default options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddWindowsAuthenticationProvider(this IServiceCollection services, string identity)
    {
        return services.AddAuthenticationProvider<WindowsAuthenticationProvider>(identity);
    }

    /// <summary>
    /// Adds the windows authentication provider as a singleton service using the given identity and options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <param name="options">The options used to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddWindowsAuthenticationProvider(this IServiceCollection services, string identity, WindowsAuthenticationProviderOptions options)
    {
        WindowsAuthenticationProvider provider = new(options);
        return services.AddAuthenticationProvider(identity, provider);
    }

    /// <summary>
    /// Adds the windows authentication provider as a transient service using the given identity and configured options.
    /// </summary>
    /// <param name="services">The collection of services</param>
    /// <param name="identity">The identity of the authentication provider</param>
    /// <param name="configure">Method invoked to configure the authentication provider</param>
    /// <returns>The collection of services.</returns>
    public static IServiceCollection AddWindowsAuthenticationProvider(this IServiceCollection services, string identity, Action<WindowsAuthenticationProviderOptions> configure)
    {
        return services.AddKeyedTransient<IAuthenticationProvider>(identity, (_, _) =>
        {
            WindowsAuthenticationProviderOptions options = new();
            configure(options);
            return new WindowsAuthenticationProvider(options);
        });
    }
}
