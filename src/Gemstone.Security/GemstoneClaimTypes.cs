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

using System.Runtime.CompilerServices;

namespace Gemstone.Security
{
    /// <summary>
    /// The Claim Types used bu the <see cref="Gemstone.Security"/> namespace 
    /// </summary>
    public static class GemstoneClaimTypes
    {
        /// <summary>
        /// Holds the unique identifier for the User.
        /// </summary>
        public const string UserIdentity = "Gemstone.UserIdentity";
        /// <summary>
        /// Holds the unique identifier for the Authentication Provider.
        /// </summary>
        public const string ProviderIdentity = "Gemstone.ProviderIdentity";

        /// <summary>
        /// Is used in Matrching Claims to match any user, regardless of claims they have
        /// </summary>
        public const string AllUsers = "Gemstone.AllUsers";

        /// <summary>
        /// Allows a user to access a resource.
        /// </summary>
        public const string AllowClaim = "Gemstone.ResourceAccess.Allow";

        /// <summary>
        /// Denies a user access to a resource.
        /// </summary>
        public const string DenyClaim = "Gemstone.ResourceAccess.Deny";

        /// <summary>
        /// Allows access to the value as the default access level.
        /// </summary>
        public const string BaseClaim = "Gemstone.ResourceAccess.Default";

    }
}
