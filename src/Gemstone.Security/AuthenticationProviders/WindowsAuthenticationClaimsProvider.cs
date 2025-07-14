//******************************************************************************************************
//  WindowsAuthenticationClaimsProvider.cs - Gbtc
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
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Gemstone.Security.AuthenticationProviders;

/// <summary>
/// Options for the <see cref="WindowsAuthenticationClaimsProvider"/> class.
/// </summary>
public class WindowsAuthenticationClaimsProviderOptions
{
    /// <summary>
    /// Root path from which LDAP searches should be performed.
    /// </summary>
    public string? LDAPPath { get; set; }
}

/// <summary>
/// Provides information about claims available to the Windows authentication provider.
/// </summary>
/// <param name="options">Options to configure the <see cref="WindowsAuthenticationClaimsProvider"/></param>
public partial class WindowsAuthenticationClaimsProvider(WindowsAuthenticationClaimsProviderOptions options) : IAuthenticationClaimsProvider
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

    private class ProviderClaim(string value, string description) : IProviderClaim
    {
        /// <summary>Group SID</summary>
        public string Value => value;

        /// <summary>FQDN (group@domain.com)</summary>
        public string Description => description;
    }

    // Constants
    private const string GroupClaim = System.Security.Claims.ClaimTypes.GroupSid;

    #endregion

    #region [ Constructors ]

    /// <summary>
    /// Creates a new instance of the <see cref="WindowsAuthenticationClaimsProvider"/> class.
    /// </summary>
    public WindowsAuthenticationClaimsProvider()
        : this(new())
    {
    }

    #endregion

    #region [ Properties ]

    private WindowsAuthenticationClaimsProviderOptions Options { get; } = options;

    #endregion

    #region [ Methods ]

    /// <inheritdoc/>
    public IReadOnlyList<string> GetClaimTypes()
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
        ArgumentOutOfRangeException.ThrowIfNotEqual(claimType, GroupClaim);

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
    private static string[] ClaimTypes { get; } = [GroupClaim];

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
