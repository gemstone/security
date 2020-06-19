//******************************************************************************************************
//  AccessControlListBuilder.cs - Gbtc
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
//  06/19/2020 - Stephen C. Wills
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;

namespace Gemstone.Security.AccessControl
{
    /// <summary>
    /// Builds access control lists for users given a collection of rules.
    /// </summary>
    /// <typeparam name="TIdentity">Type of the identifier for users.</typeparam>
    /// <typeparam name="TResource">Type of resources being accessed by users.</typeparam>
    public class AccessControlListBuilder<TIdentity, TResource>
        : IAccessControlListBuilder<TIdentity, TResource>
        where TResource : IEquatable<TResource>
    {
        private class AccessControlList : IAccessControlList<TResource>
        {
            public bool Allow { get; }
            public ISet<TResource> Resources { get; }

            public AccessControlList(bool allow, ISet<TResource> resources)
            {
                Allow = allow;
                Resources = resources;
            }

            public bool HasAccess(TResource resource) =>
                Resources.Contains(resource) ^ !Allow;
        }

        private class ResourceList
        {
            public bool Allow { get; }
            public bool Inclusive { get; }
            public IEnumerable<TResource> Resources { get; }

            public ResourceList(bool allow, bool inclusive, IEnumerable<TResource> resources)
            {
                Allow = allow;
                Inclusive = inclusive;
                Resources = resources;
            }

            public ResourceList Combine(ResourceList other)
            {
                // The logic that follows assumes this is inclusive;
                // fortunately, by changing the allow flag,
                // an exclusive list can be made inclusive
                bool allow = Allow ^ !Inclusive;
                bool sameAccessControl = allow == other.Allow;

                if (sameAccessControl && other.Inclusive)
                    return Union(other);
                else if (sameAccessControl && !other.Inclusive)
                    return ReverseExceptThenComplement(other);
                else if (!sameAccessControl && other.Inclusive)
                    return Except(other);
                else if (!sameAccessControl && !other.Inclusive)
                    return Intersect(other);

                throw new InvalidOperationException("Invalid resource list combination.");
            }

            // When two resource lists have the same access
            // control and both lists are inclusive, the
            // lists can be combined with a simple union
            private ResourceList Union(ResourceList other)
            {
                IEnumerable<TResource> resources = Resources.Union(other.Resources);
                return new ResourceList(Allow, Inclusive, resources);
            }

            // When we need "A union B" but B is exclusive:
            //   If B = X',
            //   A union B
            //     = (A' intersect B')'
            //     = (A' intersect X)'
            //     = (X intersect A')'
            //     = (X - A)'
            private ResourceList ReverseExceptThenComplement(ResourceList other)
            {
                bool complement = !Allow;
                IEnumerable<TResource> resources = other.Resources.Except(Resources);
                return new ResourceList(complement, Inclusive, resources);
            }

            // When two resource lists have different access
            // control and both lists are inclusive, the second
            // list is used to filter resources out of the first
            private ResourceList Except(ResourceList other)
            {
                IEnumerable<TResource> resources = Resources.Except(other.Resources);
                return new ResourceList(Allow, Inclusive, resources);
            }

            // When we need "A - B" but B is exclusive:
            //   If B = X',
            //   A - B
            //     = A intersect B'
            //     = A intersect X
            private ResourceList Intersect(ResourceList other)
            {
                IEnumerable<TResource> resources = Resources.Intersect(other.Resources);
                return new ResourceList(Allow, Inclusive, resources);
            }
        }

        private List<Func<TIdentity, ResourceList>> ResourceListFactories { get; }

        /// <summary>
        /// Creates a new instance of the <see cref="AccessControlListBuilder{TIdentity, TResource}"/> class.
        /// </summary>
        public AccessControlListBuilder() =>
            ResourceListFactories = new List<Func<TIdentity, ResourceList>>();

        /// <summary>
        /// Adds an allow rule to the access control list.
        /// </summary>
        /// <param name="allowedResourcesFunc">Function that returns the list of resources to be allowed.</param>
        /// <returns>The builder, for chaining.</returns>
        public IAccessControlListBuilder<TIdentity, TResource> Allow(Func<TIdentity, IEnumerable<TResource>> allowedResourcesFunc) =>
            AddResourceList(true, true, allowedResourcesFunc);

        /// <summary>
        /// Adds a deny rule to the access control list.
        /// </summary>
        /// <param name="deniedResourcesFunc">Function that returns the list of resources to be denied.</param>
        /// <returns>The builder, for chaining.</returns>
        public IAccessControlListBuilder<TIdentity, TResource> Deny(Func<TIdentity, IEnumerable<TResource>> deniedResourcesFunc) =>
            AddResourceList(false, true, deniedResourcesFunc);

        /// <summary>
        /// Adds an allow rule to the access control list.
        /// </summary>
        /// <param name="allowedResourcesFunc">Function that returns the list of resources that are not included in the rule.</param>
        /// <returns>The builder, for chaining.</returns>
        public IAccessControlListBuilder<TIdentity, TResource> AllowAllExcept(Func<TIdentity, IEnumerable<TResource>> allowedResourcesFunc) =>
            AddResourceList(true, false, allowedResourcesFunc);

        /// <summary>
        /// Adds a deny rule to the access control list.
        /// </summary>
        /// <param name="deniedResourcesFunc">Function that returns the list of resources that are not included in the rule.</param>
        /// <returns>The builder, for chaining.</returns>
        public IAccessControlListBuilder<TIdentity, TResource> DenyAllExcept(Func<TIdentity, IEnumerable<TResource>> deniedResourcesFunc) =>
            AddResourceList(false, false, deniedResourcesFunc);

        /// <summary>
        /// Creates an access control list for the given identity.
        /// </summary>
        /// <param name="identity">The identity of the user the list applies to.</param>
        /// <returns>The access control list for the given identity.</returns>
        public IAccessControlList<TResource> Build(TIdentity identity)
        {
            IEnumerable<TResource> resources = Enumerable.Empty<TResource>();
            ResourceList resourceList = new ResourceList(true, true, resources);

            foreach (Func<TIdentity, ResourceList> resourceListFactory in ResourceListFactories)
            {
                ResourceList other = resourceListFactory(identity);
                resourceList = resourceList.Combine(other);
            }

            return FromResourceList(resourceList);
        }

        private IAccessControlListBuilder<TIdentity, TResource> AddResourceList(bool allow, bool inclusive, Func<TIdentity, IEnumerable<TResource>> allowedResourcesFunc)
        {
            ResourceList CreateResourceList(TIdentity identity) =>
                new ResourceList(allow, inclusive, allowedResourcesFunc(identity));

            ResourceListFactories.Add(CreateResourceList);

            return this;
        }

        private static AccessControlList FromResourceList(ResourceList resourceList)
        {
            bool allow = resourceList.Allow ^ !resourceList.Inclusive;
            IEnumerable<TResource> resources = resourceList.Resources;
            HashSet<TResource> resourceSet = new HashSet<TResource>(resources);
            return new AccessControlList(allow, resourceSet);
        }
    }
}
