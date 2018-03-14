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
 * $Id: IdentityProviderDiscoveryUtils.cs,v 1.2 2009/06/11 18:37:58 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Utilities to assist with the Identity Provider Discovery Profile
	/// within SAMLv2.
	/// </summary>
	public static class IdentityProviderDiscoveryUtils
	{
		#region Members

		/// <summary>
		/// Obtains the next reader service during the discovery process
		/// being managed by a session variable tracking circle of trusts
		/// currently being checked.
		/// </summary>
		/// <param name="serviceProviderUtility">ServiceProviderUtility containing circle-of-trust information.</param>
		/// <returns>
		/// Returns the URL found in the currently checked circle-of-trust file if specified, null otherwise.
		/// </returns>
		public static Uri GetReaderServiceUrl(ServiceProviderUtility serviceProviderUtility)
		{
			Uri readerSvcUrl = null;

			// Obtain the list of currently tracked circle-of-trusts with
			// reader service if not already known.
			var cotList = new ArrayList();
			foreach (var cotName in serviceProviderUtility.CircleOfTrusts.Keys)
			{
				var cot = serviceProviderUtility.CircleOfTrusts[cotName];
				if (cot.ReaderServiceUrl != null)
				{
					cotList.Add(cotName);
				}
			}

			var enumerator = cotList.GetEnumerator();
			if (enumerator.MoveNext())
			{
				// Try the first service in the list
				var cotName = (string) enumerator.Current;
				var cot = serviceProviderUtility.CircleOfTrusts[cotName];
				readerSvcUrl = new Uri(cot.ReaderServiceUrl.AbsoluteUri);
			}

			return readerSvcUrl;
		}

		/// <summary>
		/// Issues a browser redirect to the specified reader service.
		/// </summary>
		/// <param name="readerServiceUrl">Location of the reader service to send redirect.</param>
		/// <param name="context">HttpContext containing session, request, and response objects.</param>
		public static void RedirectToReaderService(Uri readerServiceUrl, HttpContext context)
		{
			var request = context.Request;
			var response = context.Response;

			// Set the RelayState for the reader service to the requestede without
			// the query information already saved to the session.
			var displayUrl = request.GetDisplayUrl();
			var requestUrl = new Uri(displayUrl);
			var relayStateForReaderSvc = requestUrl.AbsoluteUri ?? string.Empty;
			if (!string.IsNullOrEmpty(requestUrl.Query))
			{
				relayStateForReaderSvc = relayStateForReaderSvc.Replace(requestUrl.Query, string.Empty);
			}

			// Redirect to the service and terminate the calling response.
			var redirectUrl = new StringBuilder();
			redirectUrl.Append(readerServiceUrl);
			redirectUrl.Append("?RelayState=");
			redirectUrl.Append(relayStateForReaderSvc);

			response.Redirect(redirectUrl.ToString(), true);
		}

		#endregion
	}
}