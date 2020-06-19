//******************************************************************************************************
//  IAccessControlListBuilder.cs - Gbtc
//
//  Copyright © 2020, Grid Protection Alliance.  All Rights Reserved.
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
//  06/18/2020 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Collections.Generic;

namespace Gemstone.Security.AccessControl
{
    /// <summary>
    /// Represents a builder for access control lists.
    /// </summary>
    /// <typeparam name="TIdentity">Type of the identifier for users.</typeparam>
    /// <typeparam name="TResource">Type of resources being accessed by users.</typeparam>
    public interface IAccessControlListBuilder<TIdentity, TResource>
    {
        /// <summary>
        /// Adds an allow rule to the access control list.
        /// </summary>
        /// <param name="allowedResourcesFunc">Function that returns the list of resources to be allowed.</param>
        /// <returns>The builder, for chaining.</returns>
        IAccessControlListBuilder<TIdentity, TResource> Allow(Func<TIdentity, IEnumerable<TResource>> allowedResourcesFunc);

        /// <summary>
        /// Adds a deny rule to the access control list.
        /// </summary>
        /// <param name="deniedResourcesFunc">Function that returns the list of resources to be denied.</param>
        /// <returns>The builder, for chaining.</returns>
        IAccessControlListBuilder<TIdentity, TResource> Deny(Func<TIdentity, IEnumerable<TResource>> deniedResourcesFunc);

        /// <summary>
        /// Adds an allow rule to the access control list.
        /// </summary>
        /// <param name="allowedResourcesFunc">Function that returns the list of resources that are not included in the rule.</param>
        /// <returns>The builder, for chaining.</returns>
        IAccessControlListBuilder<TIdentity, TResource> AllowAllExcept(Func<TIdentity, IEnumerable<TResource>> allowedResourcesFunc);

        /// <summary>
        /// Adds a deny rule to the access control list.
        /// </summary>
        /// <param name="deniedResourcesFunc">Function that returns the list of resources that are not included in the rule.</param>
        /// <returns>The builder, for chaining.</returns>
        IAccessControlListBuilder<TIdentity, TResource> DenyAllExcept(Func<TIdentity, IEnumerable<TResource>> deniedResourcesFunc);

        /// <summary>
        /// Creates an access control list for the given identity.
        /// </summary>
        /// <param name="identity">The identity of the user the list applies to.</param>
        /// <returns>The access control list for the given identity.</returns>
        IAccessControlList<TResource> Build(TIdentity identity);
    }
}
