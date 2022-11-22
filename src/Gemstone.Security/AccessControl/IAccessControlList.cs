//******************************************************************************************************
//  IAccessControlList.cs - Gbtc
//
//  Copyright © 2022, Grid Protection Alliance.  All Rights Reserved.
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

namespace Gemstone.Security.AccessControl
{
    /// <summary>
    /// Represents an access control list that can be used to
    /// determine whether a user has access to a given resource.
    /// </summary>
    /// <typeparam name="TResource">The type of resource the user is accessing.</typeparam>
    public interface IAccessControlList<TResource>
    {
        /// <summary>
        /// Indicates whether the user has access to the given resource.
        /// </summary>
        /// <param name="resource">The resource to check for access</param>
        /// <returns>True if the user has access, false otherwise</returns>
        bool HasAccess(TResource resource);
    }
}
