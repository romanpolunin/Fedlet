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
 * $Id: LogoutResponse.cs,v 1.1 2009/11/11 18:13:39 ggennaro Exp $
 */

using System;
using System.Collections.Specialized;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
    /// <summary>
    /// SAMLv2 LogoutResponse object constructed from received message after
    /// submission of a LogoutRequest from associated Identity Provider.
    /// </summary>
    public class LogoutResponse
    {
        #region Members

        /// <summary>
        /// Namespace Manager for this logout response.
        /// </summary>
        private readonly XmlNamespaceManager m_nsMgr;

        /// <summary>
        /// XML representation of the logout response.
        /// </summary>
        private readonly XmlDocument m_xml;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the LogoutResponse class.
        /// </summary>
        /// <param name="samlResponse">Decoded SAMLv2 logout response</param>
        public LogoutResponse(string samlResponse)
        {
            try
            {
                m_xml = new XmlDocument {PreserveWhitespace = true};

                m_nsMgr = new XmlNamespaceManager(m_xml.NameTable);
                m_nsMgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
                m_nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                m_nsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

                m_xml.LoadXml(samlResponse);
            }
            catch (ArgumentNullException ane)
            {
                throw new Saml2Exception(Resources.LogoutResponseNullArgument, ane);
            }
            catch (XmlException xe)
            {
                throw new Saml2Exception(Resources.LogoutResponseXmlException, xe);
            }
        }

        /// <summary>
        /// Initializes a new instance of the LogoutResponse class based on
        /// the complimentary logout request.
        /// </summary>
        /// <param name="identityProvider">
        /// IdentityProvider of the LogoutResponse
        /// </param>
        /// <param name="serviceProvider">
        /// ServiceProvider of the LogoutResponse
        /// </param>
        /// <param name="logoutRequest">
        /// Logout request that requires this response
        /// </param>
        /// <param name="parameters">
        /// NameValueCollection of varying parameters for use in the
        /// construction of the LogoutResponse.
        /// </param>
        public LogoutResponse(
            IIdentityProvider identityProvider,
            IServiceProvider serviceProvider,
            LogoutRequest logoutRequest,
            NameValueCollection parameters)
        {
            if (identityProvider == null)
            {
                throw new Saml2Exception(Resources.LogoutResponseIdentityProviderIsNull);
            }
            if (serviceProvider == null)
            {
                throw new Saml2Exception(Resources.LogoutResponseServiceProviderIsNull);
            }
            if (logoutRequest == null)
            {
                throw new Saml2Exception(Resources.LogoutResponseLogoutRequestIsNull);
            }

            if (parameters == null)
            {
                parameters = new NameValueCollection();
            }

            var inResponseToValue = logoutRequest.Id;
            var issuerValue = serviceProvider.EntityId;

            var binding = parameters[Saml2Constants.Binding];
            if (string.IsNullOrEmpty(binding))
            {
                binding = Saml2Constants.HttpPostProtocolBinding;
            }

            string idpSvcResponseLocation = null;
            if (binding != Saml2Constants.HttpSoapProtocolBinding)
            {
                idpSvcResponseLocation = identityProvider.GetSingleLogoutServiceResponseLocation(binding);
            }

            m_xml = new XmlDocument {PreserveWhitespace = true};

            m_nsMgr = new XmlNamespaceManager(m_xml.NameTable);
            m_nsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            m_nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

            var rawXml = new StringBuilder();
            rawXml.Append("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
            rawXml.Append(" ID=\"" + Saml2Utils.GenerateId() + "\" Version=\"2.0\" ");
            rawXml.Append(" IssueInstant=\"" + Saml2Utils.GenerateIssueInstant() + "\" ");

            if (idpSvcResponseLocation != null)
            {
                rawXml.Append(" Destination=\"" + idpSvcResponseLocation + "\" ");
            }

            rawXml.Append(" InResponseTo=\"" + inResponseToValue + "\">");
            rawXml.Append(" <saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + issuerValue +
                          "</saml:Issuer>");
            rawXml.Append(" <samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">");
            rawXml.Append("   <samlp:StatusCode ");
            rawXml.Append("     xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
            rawXml.Append("     Value=\"" + Saml2Constants.Success + "\">");
            rawXml.Append("   </samlp:StatusCode>");
            rawXml.Append(" </samlp:Status>");
            rawXml.Append("</samlp:LogoutResponse>");

            m_xml.LoadXml(rawXml.ToString());
        }

        #endregion

        #region Properties

        /// <summary>
        /// Gets the InResponseTo attribute value of the logout response,
        /// null if not present.
        /// </summary>
        public string InResponseTo
        {
            get
            {
                const string xpath = "/samlp:LogoutResponse";
                return Saml2Utils.TryGetAttributeValue(m_xml, m_nsMgr, xpath, "InResponseTo");
            }
        }

        /// <summary>
        /// Gets the ID attribute value of the response.
        /// </summary>
        public string Id
        {
            get
            {
                const string xpath = "/samlp:LogoutResponse";
                return Saml2Utils.RequireAttributeValue(m_xml, m_nsMgr, xpath, "InResponseTo");
            }
        }

        /// <summary>
        /// Gets the name of the issuer of the logout response.
        /// </summary>
        public string Issuer
        {
            get
            {
                const string xpath = "/samlp:LogoutResponse/saml:Issuer";
                return Saml2Utils.RequireNodeText(m_xml, m_nsMgr, xpath);
            }
        }

        /// <summary>
        /// Gets the status code of the logout response within the status element.
        /// </summary>
        public string StatusCode
        {
            get
            {
                const string xpath = "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode";
                return Saml2Utils.RequireAttributeValue(m_xml, m_nsMgr, xpath, "Value");
            }
        }

        /// <summary>
        /// Gets the status message of the logout response within the status
        /// element, null if none provided.
        /// </summary>
        public string StatusMessage
        {
            get
            {
                const string xpath = "/samlp:LogoutResponse/samlp:Status/samlp:StatusMessage";
                return Saml2Utils.TryGetNodeText(m_xml, m_nsMgr, xpath);
            }
        }

        /// <summary>
        /// Gets the XML representation of the received logout response.
        /// </summary>
        public IXPathNavigable XmlDom => m_xml;

        /// <summary>
        /// Gets the signature of the logout response attached to the
        /// response as an XML element.
        /// </summary>
        public IXPathNavigable XmlSignature
        {
            get
            {
                var xpath = "/samlp:LogoutResponse/ds:Signature";
                return Saml2Utils.TryGetNode(m_xml, m_nsMgr, xpath);
            }
        }

        #endregion

        #region Methods

        #endregion
    }
}