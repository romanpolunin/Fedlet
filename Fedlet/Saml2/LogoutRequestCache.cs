/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright (c) 2009 Sun Microsystems Inc. All Rights Reserved
 * 
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 * 
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt
 * See the License for the specific language governing
 * permission and limitations under the License.
 * 
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at opensso/legal/CDDLv1.0.txt.
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 * $Id: LogoutRequestCache.cs,v 1.1 2009/11/11 18:13:39 ggennaro Exp $
 */

using Microsoft.AspNetCore.Http;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// <para>
	/// Class managing the last X LogoutRequests associated with the
	/// user's session.  The collection of LogoutRequests are managed within
	/// a Queue added to the user's session to facilitate FIFO and allow
	/// for the ServiceProviderUtility to correctly perform validation
	/// on the LogoutRequests containing a InResponseTo attribute.
	/// </para>
	/// <para>
	/// See the MaximumRequestsStored variable for the value of X.
	/// </para>
	/// </summary>
	public static class LogoutRequestCache
	{
		#region Members

		#endregion

		#region Constructor

		#endregion

		#region Properties

		#endregion

		#region Methods

		/// <summary>
		/// Adds the specified LogoutRequest to the collection of previously 
		/// sent requests, maintaining the imposed limit as defined by 
		/// MaximumRequestsStored.  This collection is represented as a
		/// queue and is attached to the user's session.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <param name="logoutRequest">
		/// LogoutRequest to add to the collection.
		/// </param>
        internal static void AddSentLogoutRequest(HttpContext context, LogoutRequest logoutRequest)
		{
            // removed Session-based implementation, as we can't use Session to cache requests
        }

        /// <summary>
        /// Removes the LogoutRequest from the collection of previously 
        /// sent requests based on the provided LogoutRequest.Id value.
        /// This collection is represented as a queue and is attached to 
        /// the user's session.
        /// </summary>
        /// <param name="context">
        /// HttpContext containing session, request, and response objects.
        /// </param>
        /// <param name="logoutRequestId">
        /// ID of the LogoutRequest to be removed from the cache.
        /// </param>
        internal static void RemoveSentLogoutRequest(HttpContext context, string logoutRequestId)
		{
            // removed Session-based implementation, as we can't use Session to cache requests
        }

        #endregion
    }
}