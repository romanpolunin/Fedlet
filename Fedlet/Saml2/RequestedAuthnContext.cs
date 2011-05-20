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
 * $Id: RequestedAuthnContext.cs,v 1.1 2009/06/11 18:37:58 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Text;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Class representing the RequestedAuthnContext.
	/// </summary>
	public class RequestedAuthnContext
	{
		#region Members

		#endregion

		#region Constructors

		/// <summary>
		/// Initializes a new instance of the RequestedAuthnContext class.
		/// </summary>
		public RequestedAuthnContext()
		{
			Comparison = null;
			AuthnContextClassRef = new ArrayList();
			AuthnContextDeclRef = new ArrayList();
		}

		#endregion

		#region Properties

		/// <summary>
		/// Gets or sets the Comparison.
		/// </summary>
		public string Comparison { get; set; }

		/// <summary>
		/// Gets the AuthnContextClassRef.
		/// </summary>
		public ArrayList AuthnContextClassRef { get; private set; }

		/// <summary>
		/// Gets the AuthnContextDeclRef.
		/// </summary>
		public ArrayList AuthnContextDeclRef { get; private set; }

		#endregion

		#region Methods

		/// <summary>
		/// Generates the XML string of the RequestedAuthnContext using
		/// the Comparison, AuthnContextClassRef, and AuthnContextDeclRef
		/// information.
		/// </summary>
		/// <returns>Returns the RequestedAuthnContext XML as a string.</returns>
		public string GenerateXmlString()
		{
			if (AuthnContextClassRef.Count == 0 && AuthnContextDeclRef.Count == 0)
			{
				throw new Saml2Exception(Resources.RequestedAuthnContextClassRefOrDeclRefNotDefined);
			}

			if (String.IsNullOrEmpty(Comparison))
			{
				Comparison = "exact";
			}
			else if (!ValidComparison())
			{
				throw new Saml2Exception(Resources.RequestedAuthnContextInvalidComparison);
			}

			var rawXml = new StringBuilder();

			rawXml.Append("<RequestedAuthnContext Comparison=\"");
			rawXml.Append(Comparison);
			rawXml.Append("\">");

			if (AuthnContextClassRef != null)
			{
				foreach (string value in AuthnContextClassRef)
				{
					rawXml.Append("<AuthnContextClassRef>");
					rawXml.Append(value);
					rawXml.Append("</AuthnContextClassRef>");
				}
			}

			if (AuthnContextDeclRef != null)
			{
				foreach (string value in AuthnContextDeclRef)
				{
					rawXml.Append("<AuthnContextDeclRef>");
					rawXml.Append(value);
					rawXml.Append("</AuthnContextDeclRef>");
				}
			}

			rawXml.Append("</RequestedAuthnContext>");

			return rawXml.ToString();
		}

		/// <summary>
		/// Sets the AuthnContextClassRef list.
		/// </summary>
		/// <param name="list">The list to become the AuthnContextClassRef.</param>
		public void SetAuthnContextClassRef(ArrayList list)
		{
			if (list == null)
			{
				AuthnContextClassRef = new ArrayList();
			}
			else
			{
				AuthnContextClassRef = list;
			}
		}

		/// <summary>
		/// Sets the SetAuthnContextDeclRef list.
		/// </summary>
		/// <param name="list">The list to become the SetAuthnContextDeclRef.</param>
		public void SetAuthnContextDeclRef(ArrayList list)
		{
			if (list == null)
			{
				AuthnContextDeclRef = new ArrayList();
			}
			else
			{
				AuthnContextDeclRef = list;
			}
		}

		/// <summary>
		/// Checks to see if the Comparison property is set to a valid
		/// value based on the SAML specification.
		/// </summary>
		/// <returns>True if it is a valid comparison, false otherwise.</returns>
		private bool ValidComparison()
		{
			return Comparison == "exact"
			       || Comparison == "maximum"
			       || Comparison == "minimum"
			       || Comparison == "better";
		}

		#endregion
	}
}