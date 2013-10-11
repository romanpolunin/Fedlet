/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright (c) 2009-2010 Sun Microsystems Inc. All Rights Reserved
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
 * $Id: AuthnRequest.cs,v 1.2 2010/01/19 18:23:09 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Class representing the SAMLv2 AuthnRequest message for use in the
	/// SP initiated SSO profile.
	/// </summary>
	public class AuthnRequest
	{
	    /// <summary>
		/// Namespace Manager for this authn request.
		/// </summary>
		private readonly XmlNamespaceManager nsMgr;

		/// <summary>
		/// XML representation of the authn request.
		/// </summary>
		private readonly XmlDocument xml;

	    /// <summary>
	    /// Initializes a new instance of the AuthnRequest class.
	    /// </summary>
	    /// <param name="identityProvider">
	    /// IdentityProvider to receive the AuthnRequest
	    /// </param>
	    /// <param name="serviceProvider">
	    /// ServiceProvider to issue the AuthnRequest
	    /// </param>
	    /// <param name="parameters">
	    /// NameValueCollection of varying parameters for use in the 
	    /// construction of the AuthnRequest.
	    /// </param>
	    /// <param name="saml2Utils">Utilities class</param>
	    public AuthnRequest(IIdentityProvider identityProvider, IServiceProvider serviceProvider, NameValueCollection parameters, Saml2Utils saml2Utils)
		{
			xml = new XmlDocument();
			xml.PreserveWhitespace = true;

			nsMgr = new XmlNamespaceManager(xml.NameTable);
			nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
			nsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            Id = saml2Utils.GenerateId();
            IssueInstant = saml2Utils.GenerateIssueInstant();
			Issuer = serviceProvider.EntityId;

			if (parameters != null)
			{
                AllowCreate = saml2Utils.GetBoolean(parameters[Saml2Constants.AllowCreate]);
				AssertionConsumerServiceIndex = parameters[Saml2Constants.AssertionConsumerServiceIndex];
				Binding = parameters[Saml2Constants.Binding];
				Consent = parameters[Saml2Constants.Consent];
				Destination = parameters[Saml2Constants.Destination];
                ForceAuthn = saml2Utils.GetBoolean(parameters[Saml2Constants.ForceAuthn]);
                IsPassive = saml2Utils.GetBoolean(parameters[Saml2Constants.IsPassive]);
			    NameIDPolicyFormat = parameters[Saml2Constants.NameIDPolicyFormat];
			}

			string assertionConsumerSvcUrl = null;
			if (!String.IsNullOrEmpty(Binding))
			{
				if (!String.IsNullOrEmpty(AssertionConsumerServiceIndex))
				{
					// find assertion consumer service location by binding and index.
					assertionConsumerSvcUrl = serviceProvider.GetAssertionConsumerServiceLocation(Binding,
					                                                                              AssertionConsumerServiceIndex);
				}
				else
				{
					// find assertion consumer service location by binding only, using first found.
					assertionConsumerSvcUrl = serviceProvider.GetAssertionConsumerServiceLocation(Binding);
				}
			}

			// neither index nor binding, throw exception
			if (String.IsNullOrEmpty(AssertionConsumerServiceIndex) && String.IsNullOrEmpty(assertionConsumerSvcUrl))
			{
				throw new Saml2Exception(Resources.AuthnRequestAssertionConsumerServiceNotDefined);
			}

			// If destination not specified, use SSO location by binding
			if (string.IsNullOrEmpty(Destination))
			{
				Destination
					= identityProvider.GetSingleSignOnServiceLocation(parameters[Saml2Constants.RequestBinding]);

				if (string.IsNullOrEmpty(Destination))
				{
					// default to HttpRedirect
					Destination = identityProvider.GetSingleSignOnServiceLocation(Saml2Constants.HttpRedirectProtocolBinding);
				}
			}

			// Get RequestedAuthnContext if parameters are available...
			RequestedAuthnContext reqAuthnContext = GetRequestedAuthnContext(serviceProvider, parameters);

			// Generate the XML for the AuthnRequest...
			var rawXml = new StringBuilder();
			rawXml.Append("<samlp:AuthnRequest ");
			rawXml.Append(" xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"");
			rawXml.Append(" ID=\"" + Id + "\"");
			rawXml.Append(" Version=\"2.0\"");
			rawXml.Append(" IssueInstant=\"" + IssueInstant + "\"");
			rawXml.Append(" IsPassive=\"" + IsPassive.ToString().ToLower() + "\"");
            rawXml.Append(" ForceAuthn=\"" + ForceAuthn.ToString().ToLower() + "\"");

			if (!String.IsNullOrEmpty(Consent))
			{
				rawXml.Append(" Consent=\"" + Consent + "\"");
			}

			if (!String.IsNullOrEmpty(Destination))
			{
				rawXml.Append(" Destination=\"" + Destination + "\"");
			}

			if (!String.IsNullOrEmpty(assertionConsumerSvcUrl))
			{
				rawXml.Append(" ProtocolBinding=\"" + Binding + "\"");
				rawXml.Append(" AssertionConsumerServiceURL=\"" + assertionConsumerSvcUrl + "\"");
			}
			else
			{
				rawXml.Append(" AssertionConsumerIndex=\"" + AssertionConsumerServiceIndex + "\"");
			}

			rawXml.Append(">");
			rawXml.Append("<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + serviceProvider.EntityId +
			              "</saml:Issuer>");

            rawXml.Append("<samlp:NameIDPolicy Format=\"" + NameIDPolicyFormat + "\" AllowCreate=\"" + AllowCreate.ToString().ToLower() + "\" />");
			
            if (reqAuthnContext != null)
			{
				rawXml.Append(reqAuthnContext.GenerateXmlString());
			}
            
            rawXml.Append("</samlp:AuthnRequest>");

			xml.LoadXml(rawXml.ToString());
		}

	    /// <summary>
		/// Gets a value indicating whether AllowCreate is true or false.
		/// </summary>
		public bool AllowCreate { get; private set; }

        /// <summary>
        /// The NameIDPolicy Format requested by the IdP 
        /// </summary>
        public string NameIDPolicyFormat { get; private set; }

		/// <summary>
		/// Gets the AssertionConsumerServiceIndex.
		/// </summary>
		public string AssertionConsumerServiceIndex { get; private set; }

		/// <summary>
		/// Gets the Binding.
		/// </summary>
		public string Binding { get; private set; }

		/// <summary>
		/// Gets the Consent.
		/// </summary>
		public string Consent { get; private set; }

		/// <summary>
		/// Gets the Destination.
		/// </summary>
		public string Destination { get; private set; }

		/// <summary>
		/// Gets a value indicating whether ForceAuthn is true or false.
		/// </summary>
		public bool ForceAuthn { get; private set; }

		/// <summary>
		/// Gets the ID.
		/// </summary>
		public string Id { get; private set; }

		/// <summary>
		/// Gets a value indicating whether IsPassive is true or false.
		/// </summary>
		public bool IsPassive { get; private set; }

		/// <summary>
		/// Gets the Issuer.
		/// </summary>
		public string Issuer { get; private set; }

		/// <summary>
		/// Gets the IssueInstant.
		/// </summary>
		public string IssueInstant { get; private set; }

		/// <summary>
		/// Gets the XML representation of the received authn response.
		/// </summary>
		public IXPathNavigable XmlDom
		{
			get { return xml; }
		}

	    /// <summary>
		/// Getst the RequestedAuthnContext element based on supplied 
		/// parameters for the given service provider.
		/// <seealso cref="Saml2Constants.AuthnContextClassRef"/>
		/// <seealso cref="Saml2Constants.AuthnContextDeclRef"/>
		/// <seealso cref="Saml2Constants.AuthLevel"/>
		/// </summary>
		/// <param name="serviceProvider">
		/// Service Provider generating the RequestedAuthnContext.
		/// </param>
		/// <param name="parameters">
		/// NameValueCollection containing necessary parameters for 
		/// constructing the RequetedAuthnContext.
		/// </param>
		/// <returns>RequestedAuthContext object or null if parameters are not present.</returns>
		private static RequestedAuthnContext GetRequestedAuthnContext(IServiceProvider serviceProvider,
		                                                              NameValueCollection parameters)
		{
			RequestedAuthnContext reqAuthnContext = null;

			if (!String.IsNullOrEmpty(parameters[Saml2Constants.AuthnContextClassRef])
			    || !String.IsNullOrEmpty(parameters[Saml2Constants.AuthnContextDeclRef])
			    || !String.IsNullOrEmpty(parameters[Saml2Constants.AuthLevel]))
			{
				reqAuthnContext = new RequestedAuthnContext();
				var classRefs = new ArrayList();
				var declRefs = new ArrayList();

				char[] separators = {'|'};
				if (!String.IsNullOrEmpty(parameters[Saml2Constants.AuthnContextClassRef]))
				{
					classRefs.AddRange(parameters[Saml2Constants.AuthnContextClassRef].Split(separators));
				}

				if (!String.IsNullOrEmpty(parameters[Saml2Constants.AuthnContextDeclRef]))
				{
					declRefs.AddRange(parameters[Saml2Constants.AuthnContextDeclRef].Split(separators));
				}

				if (!String.IsNullOrEmpty(parameters[Saml2Constants.AuthLevel]))
				{
					int authLevel = Convert.ToInt32(parameters[Saml2Constants.AuthLevel], CultureInfo.InvariantCulture);
					classRefs.Add(serviceProvider.GetAuthnContextClassRefFromAuthLevel(authLevel));
				}

				reqAuthnContext.SetAuthnContextClassRef(classRefs);
				reqAuthnContext.SetAuthnContextDeclRef(declRefs);

				if (!String.IsNullOrEmpty(parameters[Saml2Constants.AuthComparison]))
				{
					reqAuthnContext.Comparison = parameters[Saml2Constants.AuthComparison];
				}
			}

			return reqAuthnContext;
		}
	}
}