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
 * $Id: CircleOfTrust.cs,v 1.2 2009/05/19 16:01:03 ggennaro Exp $
 */

using System;
using System.Collections.Generic;
using System.Collections.Specialized;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Circle Of Trust (COT) for the Fedlet in the ASP.NET environment. 
	/// </summary>
	public class CircleOfTrust : ICircleOfTrust
	{
		private const string CircleOfTrustNameAttribute = "cot-name";
		private const string Saml2ReaderServiceKey = "sun-fm-saml2-readerservice-url";
		private const string Saml2WriterServiceKey = "sun-fm-saml2-writerservice-url";
		private const string TrustedProvidersKey = "sun-fm-trusted-providers";

		private readonly HashSet<string> m_trustedEntities = new HashSet<string>();


		/// <summary>
		/// Gets the name of the circle of trust
		/// </summary>
		public string Name { get; }

		/// <summary>
		/// Gets the saml2 reader service url, empty string if not specified,
		/// null attribute is not found.
		/// </summary>
		public Uri ReaderServiceUrl { get; }

		/// <summary>
		/// Gets the saml2 writer service url, empty string if not specified,
		/// null attribute is not found.
		/// </summary>
		public Uri WriterServiceUrl { get; }

		/// <summary>
		/// Initializes a new instance of the CircleOfTrust class.
		/// </summary>
		/// <param name="attributes">name-value pair collection of attributes.</param>
		public CircleOfTrust(NameValueCollection attributes)
		{
			Name = attributes[CircleOfTrustNameAttribute];

			string value = attributes[Saml2ReaderServiceKey];
			ReaderServiceUrl = string.IsNullOrEmpty(value) ? null : new Uri(value);

			value = attributes[Saml2WriterServiceKey];
			WriterServiceUrl = string.IsNullOrEmpty(value) ? null : new Uri(value);
			
			string trusted = attributes[TrustedProvidersKey];

			if (trusted != null)
			{
				string[] separator = {","};

				foreach (var t in trusted.Split(separator, StringSplitOptions.RemoveEmptyEntries))
				{
					m_trustedEntities.Add(t.Trim());
				}
			}
		}

		/// <summary>
		/// Checks service provider and identity provider Entity ID's to
		/// ensure they are found in the Trusted Providers property.
		/// </summary>
		/// <param name="serviceProviderEntityId">Service Provider EntityID</param>
		/// <param name="identityProviderEntityId">Identity Provider EntityID</param>
		/// <returns>True if providers are trusted, false otherwise.</returns>
		public bool AreProvidersTrusted(string serviceProviderEntityId, string identityProviderEntityId)
		{
			return m_trustedEntities.Contains(serviceProviderEntityId)
			       && m_trustedEntities.Contains(identityProviderEntityId);
		}
	}
}