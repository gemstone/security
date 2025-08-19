//******************************************************************************************************
//  ResourceAccessLevel.cs - Gbtc
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
//  02/24/2025 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

namespace Gemstone.Security.AccessControl;

/// <summary>
/// Represents the default access levels that can apply to a resource.
/// </summary>
public enum ResourceAccessLevel
{
    /// <summary>
    /// View-only access (read, status, ...)
    /// </summary>
    View,

    /// <summary>
    /// Basic level of configuration (start/stop adapters, update connection strings, ...)
    /// </summary>
    Edit,

    /// <summary>
    /// Administrative level of configuration (users, roles, permissions, config files, ...)
    /// </summary>
    Admin,

    /// <summary>
    /// Dangerous level of configuration that can be enabled
    /// for convenience or necessity (upload files to server, ...)
    /// </summary>
    Special
}
