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
 * $Id: AuthnResponse.cs,v 1.5 2009/11/11 18:13:39 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Globalization;
using System.Xml;
using System.Xml.XPath;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
    /// <summary>
    ///     SAMLv2 AuthnResponse object constructed from a response obtained from
    ///     an Identity Provider for the hosted Service Provider.
    /// </summary>
    public class AuthnResponse
    {
        #region Constructors

        /// <summary>
        ///     Initializes a new instance of the AuthnResponse class.
        /// </summary>
        /// <param name="samlResponse">Decoded SAMLv2 Response</param>
        public AuthnResponse(string samlResponse)
        {
            try
            {
                _xml = new XmlDocument {PreserveWhitespace = true};
                _xml.LoadXml(samlResponse);
                _nsMgr = new XmlNamespaceManager(_xml.NameTable);
                _nsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
                _nsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                _nsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            }
            catch (ArgumentNullException ane)
            {
                throw new Saml2Exception(Resources.AuthnResponseNullArgument, ane);
            }
            catch (XmlException xe)
            {
                throw new Saml2Exception(Resources.AuthnResponseXmlException, xe);
            }
        }

        #endregion

        #region Members

        /// <summary>
        ///     Namespace Manager for this authn response.
        /// </summary>
        private readonly XmlNamespaceManager _nsMgr;

        /// <summary>
        ///     XML representation of the authn response.
        /// </summary>
        private readonly XmlDocument _xml;

        #endregion

        #region Properties

        /// <summary>
        ///     Gets the XML representation of the received authn response.
        /// </summary>
        public IXPathNavigable XmlDom => _xml;

        /// <summary>
        ///     Gets the signature of the authn response attached to the
        ///     assertion as an XML element.
        /// </summary>
        public IXPathNavigable XmlAssertionSignature
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/ds:Signature";
                return Saml2Utils.RequireRootElement(_xml).SelectSingleNode(xpath, _nsMgr);
            }
        }

        /// <summary>
        ///     Gets the signature of the authn response attached to the
        ///     response as an XML element.
        /// </summary>
        public IXPathNavigable XmlResponseSignature
        {
            get
            {
                const string xpath = "/samlp:Response/ds:Signature";
                return Saml2Utils.RequireRootElement(_xml).SelectSingleNode(xpath, _nsMgr);
            }
        }

        /// <summary>
        ///     Gets the Assertion ID attribute value of the response.
        /// </summary>
        public string AssertionId
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion";
                return Saml2Utils.RequireAttributeValue(_xml, _nsMgr, xpath, "ID");
            }
        }

        /// <summary>
        ///     Gets the ID attribute value of the response.
        /// </summary>
        public string Id
        {
            get
            {
                const string xpath = "/samlp:Response";
                return Saml2Utils.RequireAttributeValue(_xml, _nsMgr, xpath, "ID");
            }
        }

        /// <summary>
        ///     Gets the InResponseTo attribute value of the authn response, null
        ///     if not present.
        /// </summary>
        public string InResponseTo
        {
            get
            {
                const string xpath = "/samlp:Response";
                return Saml2Utils.TryGetAttributeValue(_xml, _nsMgr, xpath, "InResponseTo");
            }
        }

        /// <summary>
        ///     Gets the name of the issuer of the authn response.
        /// </summary>
        public string Issuer
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Issuer";
                return Saml2Utils.RequireNodeText(_xml, _nsMgr, xpath);
            }
        }

        /// <summary>
        ///     Gets the status code of the authn response within the status element.
        /// </summary>
        public string StatusCode
        {
            get
            {
                const string xpath = "/samlp:Response/samlp:Status/samlp:StatusCode";
                return Saml2Utils.RequireAttributeValue(_xml, _nsMgr, xpath, "Value");
            }
        }

        /// <summary>
        ///     Gets the X509 signature certificate of the authn response attached
        ///     to the assertion, null if none provided.
        /// </summary>
        public string AssertionSignatureCertificate
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate";
                return Saml2Utils.TryGetNodeText(_xml, _nsMgr, xpath);
            }
        }

        /// <summary>
        ///     Gets the X509 signature certificate of the authn response attached
        ///     to the response, null if none provided.
        /// </summary>
        public string ResponseSignatureCertificate
        {
            get
            {
                const string xpath = "/samlp:Response/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate";
                return Saml2Utils.TryGetNodeText(_xml, _nsMgr, xpath);
            }
        }

        /// <summary>
        ///     Gets the session index within the authn statement within the authn
        ///     response assertion.
        /// </summary>
        public string SessionIndex
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/saml:AuthnStatement";
                return Saml2Utils.TryGetAttributeValue(_xml, _nsMgr, xpath, "SessionIndex");
            }
        }

        /// <summary>
        ///     Gets the name ID of the subject within the authn response assertion.
        /// </summary>
        public string SubjectNameId
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";
                return Saml2Utils.TryGetNodeText(_xml, _nsMgr, xpath);
            }
        }

        /// <summary>
        ///     Gets the extracted "NotBefore" condition from the authn response.
        /// </summary>
        public DateTime ConditionNotBefore
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/saml:Conditions";
                var value = Saml2Utils.RequireAttributeValue(_xml, _nsMgr, xpath, "NotBefore");
                return DateTime.Parse(value, CultureInfo.InvariantCulture);
            }
        }

        /// <summary>
        ///     Gets the extracted "NotOnOrAfter" condition from the authn response.
        /// </summary>
        public DateTime ConditionNotOnOrAfter
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/saml:Conditions";
                var value = Saml2Utils.RequireAttributeValue(_xml, _nsMgr, xpath, "NotOnOrAfter");
                return DateTime.Parse(value, CultureInfo.InvariantCulture);
            }
        }

        /// <summary>
        ///     Gets the list containing string of entity ID's that are considered
        ///     appropriate audiences for this authn response.
        /// </summary>
        public ArrayList ConditionAudiences
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience";
                var root = Saml2Utils.RequireRootElement(_xml);
                var nodeList = root.SelectNodes(xpath, _nsMgr);
                var audiences = new ArrayList();

                var nodes = nodeList?.GetEnumerator();
                if (nodes != null)
                {
                    while (nodes.MoveNext())
                    {
                        var node = (XmlNode) nodes.Current;
                        audiences.Add(node.InnerText.Trim());
                    }
                }

                return audiences;
            }
        }

        /// <summary>
        ///     Gets the property containing the attributes provided in the SAML2
        ///     assertion, if provided, otherwise an empty hashtable.
        /// </summary>
        public Hashtable Attributes
        {
            get
            {
                const string xpath = "/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute";
                var root = Saml2Utils.RequireRootElement(_xml);
                var nodeList = root.SelectNodes(xpath, _nsMgr);
                var attributes = new Hashtable();

                var nodes = nodeList?.GetEnumerator();
                if (nodes != null)
                {
                    while (nodes.MoveNext())
                    {
                        var samlAttribute = (XmlNode) nodes.Current;
                        if (samlAttribute.Attributes != null)
                        {
                            var name = samlAttribute.Attributes["Name"].Value.Trim();

                            var samlAttributeValues = samlAttribute.SelectNodes(
                                "descendant::saml:AttributeValue", _nsMgr);
                            var values = new ArrayList();
                            if (samlAttributeValues != null)
                            {
                                foreach (XmlNode node in samlAttributeValues)
                                {
                                    var value = node.InnerText.Trim();
                                    values.Add(value);
                                }

                                attributes.Add(name, values);
                            }
                        }
                    }
                }

                return attributes;
            }
        }

        #endregion

        #region Methods

        #endregion
    }
}