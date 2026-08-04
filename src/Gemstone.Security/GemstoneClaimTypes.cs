//******************************************************************************************************
//  GemstoneClaimTypes.cs - Gbtc
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
//  10/16/2019 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

namespace Gemstone.Security
{
    /// <summary>
    /// The claim types used by the <see cref="Security"/> namespace.
    /// </summary>
    public static class GemstoneClaimTypes
    {
        /// <summary>
        /// Assigned claim that holds the unique identifier for the User.
        /// </summary>
        public const string UserIdentity = "Gemstone.UserIdentity";

        /// <summary>
        /// Assigned claim that holds the unique identifier for the Authentication Provider.
        /// </summary>
        public const string ProviderIdentity = "Gemstone.ProviderIdentity";

        /// <summary>
        /// Implicit claim that masquerades as a provider claim and applies
        /// to any user principal regardless of what claims they have.
        /// </summary>
        public const string AllUsers = "Gemstone.AllUsers";

        /// <summary>
        /// Assigned claim that allows a user to access a resource.
        /// </summary>
        public const string AllowClaim = "Gemstone.ResourceAccess.Allow";

        /// <summary>
        /// Assigned claim that denies a user access to a resource.
        /// </summary>
        public const string DenyClaim = "Gemstone.ResourceAccess.Deny";

        /// <summary>
        /// Assigned claim that allows access to the value as the default access level.
        /// </summary>
        public const string BaseClaim = "Gemstone.ResourceAccess.Default";
    }
}
