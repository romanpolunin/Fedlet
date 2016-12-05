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
 * $Id: ArtifactResponse.cs,v 1.2 2009/11/11 18:13:39 ggennaro Exp $
 */

using System;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.XPath;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// SAMLv2 ArtifactResponse object constructed from a response obtained 
	/// from an Identity Provider for the hosted Service Provider.
	/// </summary>
	public class ArtifactResponse
	{
		#region Members

	    /// <summary>
		/// Namespace Manager for this authn response.
		/// </summary>
		private readonly XmlNamespaceManager _nsMgr;

		/// <summary>
		/// XML representation of the authn response.
		/// </summary>
		private readonly XmlDocument _xml;

		#endregion

		#region Constructors

		/// <summary>
		/// Initializes a new instance of the ArtifactResponse class.
		/// </summary>
		/// <param name="artifactResponse">
		/// String representation of the ArtifactResponse xml.
		/// </param>
		public ArtifactResponse(string artifactResponse)
		{
			try
			{
			    _xml = new XmlDocument {PreserveWhitespace = true};
			    _xml.LoadXml(artifactResponse);
				_nsMgr = new XmlNamespaceManager(_xml.NameTable);
				_nsMgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
				_nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
				_nsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

				const string xpath = "/samlp:ArtifactResponse/samlp:Response";
				var response = _xml.DocumentElement?.SelectSingleNode(xpath, _nsMgr);
				if (response == null)
				{
					throw new Saml2Exception(Resources.ArtifactResponseMissingResponse);
				}

				AuthnResponse = new AuthnResponse(response.OuterXml);
			}
			catch (ArgumentNullException ane)
			{
				throw new Saml2Exception(Resources.ArtifactResponseNullArgument, ane);
			}
			catch (XmlException xe)
			{
				throw new Saml2Exception(Resources.ArtifactResponseXmlException, xe);
			}
		}

        #endregion

        #region Properties

        /// <summary>
        /// Gets the AuthnResponse object enclosed in the artifact response.
        /// <c>null</c> if none provided.
        /// </summary>
        public AuthnResponse AuthnResponse { get; }

        /// <summary>
        /// Gets the ID attribute value of the artifact response.
        /// Throws if none provided.
        /// </summary>
        public string Id
		{
			get
			{
				const string xpath = "/samlp:ArtifactResponse";
                return Saml2Utils.RequireAttributeValue(_xml, _nsMgr, xpath, "ID");
			}
		}

        /// <summary>
        /// Gets the InResponseTo attribute value of the artifact response, 
        /// <c>null</c> if none provided.
        /// </summary>
        public string InResponseTo
		{
			get
			{
				const string xpath = "/samlp:ArtifactResponse";
                return Saml2Utils.TryGetAttributeValue(_xml, _nsMgr, xpath, "InResponseTo");
            }
		}

		/// <summary>
		/// Gets the name of the issuer of the artifact response.
		/// Throws if none provided.
		/// </summary>
		public string Issuer
		{
			get
			{
			    const string xpath = "/samlp:ArtifactResponse/saml:Issuer";
			    return Saml2Utils.RequireNodeText(_xml, _nsMgr, xpath);
			}
		}

		/// <summary>
		/// Gets the X509 signature certificate of the artifact response,
		/// <c>null</c> if none provided.
		/// </summary>
		public string SignatureCertificate
		{
			get
			{
				const string xpath = "/samlp:ArtifactResponse/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate";
			    return Saml2Utils.TryGetNodeText(_xml, _nsMgr, xpath);
			}
		}

        /// <summary>
        /// Gets the signature of the artifact response as an XML element.
        /// <c>null</c> if none provided.
        /// </summary>
        public IXPathNavigable XmlSignature
		{
			get
			{
				const string xpath = "/samlp:ArtifactResponse/ds:Signature";
			    return Saml2Utils.TryGetNode(_xml, _nsMgr, xpath);
			}
		}

        /// <summary>
        /// Gets the XML representation of the received artifact response.
        /// <c>null</c> if none provided.
        /// </summary>
        public IXPathNavigable XmlDom => _xml;

	    #endregion

		#region Methods

		#endregion
	}
}