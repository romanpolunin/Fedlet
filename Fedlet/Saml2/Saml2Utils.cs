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
 * $Id: Saml2Utils.cs,v 1.8 2010/01/26 01:20:14 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Xml;
using System.Xml.XPath;
using Microsoft.AspNetCore.Http;
using Sun.Identity.Common;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
	/// <summary>
	/// Utility class for performing SAMLv2 operations.
	/// </summary>
	public class Saml2Utils
	{
	    private readonly IFedletCertificateFactory _certificateFactory;

	    /// <summary>
	    /// Ctr.
	    /// </summary>
        public Saml2Utils(IFedletCertificateFactory certificateFactory)
        {
            _certificateFactory = certificateFactory;
        }

	    /// <summary>
		/// Converts the string from the base64 encoded input.
		/// </summary>
		/// <param name="value">Base64 encoded string.</param>
		/// <returns>String contained within the base64 encoded string.</returns>
		public string ConvertFromBase64(string value)
		{
			var byteArray = Convert.FromBase64String(value);
			return Encoding.UTF8.GetString(byteArray);
		}

        /// <summary>
        /// Converts from Base64, then decompresses the given
        /// parameter and returns the ensuing string.
        /// </summary>
        /// <param name="message">message to undergo the process</param>
        /// <returns>String output from the process.</returns>
        public string ConvertFromBase64Decompress(string message)
        {
            // convert from base 64
            var byteArray = Convert.FromBase64String(message);

            // inflate the gzip deflated message
            var streamReader = new StreamReader(new DeflateStream(new MemoryStream(byteArray), CompressionMode.Decompress));

            // put in a string
            var decompressedMessage = streamReader.ReadToEnd();
            streamReader.Close();

            return decompressedMessage;
        }

        /// <summary>
        /// Converts the base64 encoded string of the given input string.
        /// </summary>
        /// <param name="value">String to be encoded.</param>
        /// <returns>Base64 encoded output of the specified string.</returns>
        public string ConvertToBase64(string value)
		{
			return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
		}

		/// <summary>
		/// Creates a SOAP message, with no header, to encompass the specified
		/// xml payload in its body.
		/// </summary>
		/// <param name="xmlPayload">XML to be placed within the body of this message.</param>
		/// <returns>String representation of the SOAP message.</returns>
		public string CreateSoapMessage(string xmlPayload)
		{
			var soapMessage = new StringBuilder();
			soapMessage.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
			soapMessage.Append("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" >");
			soapMessage.Append("  <soap:Body>");
			soapMessage.Append(xmlPayload);
			soapMessage.Append("  </soap:Body>");
			soapMessage.Append("</soap:Envelope>");

			return soapMessage.ToString();
		}

		/// <summary>
		/// Generates a random ID for use in SAMLv2 assertions, requests, and
		/// responses.
		/// </summary>
		/// <returns>String representing a random ID with length specified by Saml2Constants.IdLength</returns>
		public string GenerateId()
		{
			var random = new Random();
			var byteArray = new byte[Saml2Constants.IdLength - 1];
			random.NextBytes(byteArray);
			var id = "A" + BitConverter.ToString(byteArray).Replace("-", string.Empty);

			return id;
		}

		/// <summary>
		/// Generates the current time, in UTC, formatted in the invariant
		/// culture format for use in SAMLv2 assertions, requests, and
		/// responses.
		/// </summary>
		/// <returns>Current time in UTC, invariant culture format.</returns>
		public string GenerateIssueInstant()
		{
			var issueInstant = DateTime.UtcNow.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'", DateTimeFormatInfo.InvariantInfo);

			return issueInstant;
		}

		/// <summary>
		/// Gets the request parameters and returns them within a NameValueCollection.
		/// </summary>
		/// <param name="request">HttpRequest containing desired parameters</param>
		/// <returns>
		/// NameValueCOllection of parameters found in QueryString and Form objects within
		/// the given Request.
		/// </returns>
		public NameValueCollection GetRequestParameters(HttpRequest request)
		{
			var parameters = new NameValueCollection();

			foreach (string name in request.Query.Keys)
			{
				parameters[name] = request.Query[name];
			}

		    if (request.HasFormContentType)
		    {
		        foreach (string name in request.Form.Keys)
		        {
		            parameters[name] = request.Form[name];
		        }
		    }

			return parameters;
		}

		/// <summary>
		/// Gets the boolean value from the string using Boolean.Parse(string)
		/// but handles exception.
		/// </summary>
		/// <param name="value">String to parse.</param>
		/// <returns>
		/// Results from Boolean.Parse(string), false if exception thrown.
		/// </returns>
		public static bool GetBoolean(string value)
		{
		    return bool.TryParse(value, out var result) && result;
		}

		/// <summary>
		/// Gets the delimiter in the context of a query string depending
		/// on the existence of a question mark within the given URL.
		/// </summary>
		/// <param name="location">
		/// URL location to check for the presence of the question mark.
		/// </param>
		/// <returns>
		/// Returns &quot; if it doesn't currently exist in the given URL, otherwise
		/// &amp; is returned.
		/// </returns>
        public static string GetQueryStringDelimiter(string location)
		{
		    if (location == null)
		    {
		        throw new ArgumentNullException(nameof(location));
		    }

            return location.Contains("?") ? "&" : "?";
		}

	    /// <summary>
		/// Compresses, converts to Base64, then URL encodes the given
		/// parameter and returns the ensuing string.
		/// </summary>
		/// <param name="xml">XML to undergo the process</param>
		/// <returns>String output from the process.</returns>
		public string CompressConvertToBase64UrlEncode(IXPathNavigable xml)
		{
			var xmlDoc = (XmlDocument) xml;

			var buffer = Encoding.UTF8.GetBytes(xmlDoc.OuterXml);
			var memoryStream = new MemoryStream();
			var compressedStream = new DeflateStream(memoryStream, CompressionMode.Compress, true);
			compressedStream.Write(buffer, 0, buffer.Length);
			compressedStream.Close();

			memoryStream.Position = 0;
			var compressedBuffer = new byte[memoryStream.Length];
			memoryStream.Read(compressedBuffer, 0, compressedBuffer.Length);
			memoryStream.Close();

			var compressedBase64String = Convert.ToBase64String(compressedBuffer);
			var compressedBase64UrlEncodedString = HttpUtility.UrlEncode(compressedBase64String);

			return compressedBase64UrlEncodedString;
		}

		/// <summary>
		/// URL decodes, converts from Base64, then decompresses the given
		/// parameter and returns the ensuing string.
		/// </summary>
		/// <param name="message">message to undergo the process</param>
		/// <returns>String output from the process.</returns>
		public string UrlDecodeConvertFromBase64Decompress(string message)
		{
            // url decode it
			var decodedMessage = HttpUtility.UrlDecode(message);

            if (string.IsNullOrEmpty(decodedMessage))
            {
                throw new ArgumentException("Empty message");
            }

            // convert from base 64
			var byteArray = Convert.FromBase64String(decodedMessage);

			// inflate the gzip deflated message
			var streamReader = new StreamReader(new DeflateStream(new MemoryStream(byteArray), CompressionMode.Decompress));

			// put in a string
			var decompressedMessage = streamReader.ReadToEnd();
			streamReader.Close();

			return decompressedMessage;
		}

		/// <summary>
		/// Signs the specified query string with the certificate found in the
		/// local machine matching the provided friendly name.  The algorithm
		/// is expected to be one of the parameters in the query string.
		/// </summary>
		/// <param name="certFriendlyName">
		/// Friendly Name of the X509Certificate to be retrieved
		/// from the LocalMachine keystore and used to sign the xml document.
		/// Be sure to have appropriate permissions set on the keystore.
		/// </param>
		/// <param name="queryString">Query string to sign.</param>
		/// <returns>
		/// A signed query string where a digital signature is added.
		/// </returns>
		public string SignQueryString(string certFriendlyName, string queryString)
		{
		    if (string.IsNullOrEmpty(certFriendlyName))
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringInvalidCertFriendlyName);
		    }

		    if (string.IsNullOrEmpty(queryString))
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringInvalidQueryString);
		    }

		    char[] queryStringSep = {'&'};
		    var queryParams = new NameValueCollection();
		    foreach (var pairs in queryString.Split(queryStringSep))
		    {
		        var key = pairs.Substring(0, pairs.IndexOf("=", StringComparison.Ordinal));
		        var value = pairs.Substring(pairs.IndexOf("=", StringComparison.Ordinal) + 1);

		        queryParams[key] = value;
		    }

		    if (string.IsNullOrEmpty(queryParams[Saml2Constants.SignatureAlgorithm]))
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringSigAlgMissing);
		    }

		    var cert = _certificateFactory.GetCertificateByFriendlyName(certFriendlyName);
		    if (cert == null)
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringCertNotFound);
		    }

		    if (!cert.HasPrivateKey)
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringCertHasNoPrivateKey);
		    }

		    var signatureAlgorithmUrl = HttpUtility.UrlDecode(queryParams[Saml2Constants.SignatureAlgorithm]);
		    var hashAlgorithmName = GetHashAlgorithmNameFromSignatureAlgorithmUrl(signatureAlgorithmUrl);

		    using (var signingKey = cert.GetRSAPrivateKey())
		    {
		        var privateKey = signingKey;
		        var signature = privateKey.SignData(Encoding.UTF8.GetBytes(queryString), hashAlgorithmName, RSASignaturePadding.Pkcs1);

		        var encodedSignature = Convert.ToBase64String(signature);

		        var signedQueryString
		            = queryString
		              + "&" + Saml2Constants.Signature
		              + "=" + HttpUtility.UrlEncode(encodedSignature);

		        return signedQueryString;
		    }
		}

        /// <summary>
        /// Determines hash algorithm name based on signature algorithm.
        /// </summary>
        /// <see cref="HashAlgorithmName.SHA1"/>
        /// <see cref="HashAlgorithmName.SHA256"/>
        /// <see cref="HashAlgorithmName.SHA384"/>
        /// <see cref="HashAlgorithmName.SHA512"/>
        public static HashAlgorithmName GetHashAlgorithmNameFromSignatureAlgorithmUrl(string signatureAlgorithmUrl)
	    {
            switch (signatureAlgorithmUrl)
            {
                case SignedXml.XmlDsigDSAUrl:
                    return HashAlgorithmName.SHA1;

                case SignedXml.XmlDsigRSASHA1Url:
                    return HashAlgorithmName.SHA1;

                case InternalSignedXml.XmlDsigRSASHA256Url:
                    return HashAlgorithmName.SHA256;

                case InternalSignedXml.XmlDsigRSASHA384Url:
                    return HashAlgorithmName.SHA384;

                case InternalSignedXml.XmlDsigRSASHA512Url:
                    return HashAlgorithmName.SHA512;

                default:
                    throw new Saml2Exception(Resources.SignedQueryStringSigAlgNotSupported);
            }
        }

        /// <summary>
        /// Signs the specified xml document with the certificate found in
        /// the local machine matching the provided friendly name and
        /// referring to the specified target reference ID.
        /// </summary>
        /// <param name="certFriendlyName">
        /// Friendly Name of the X509Certificate to be retrieved
        /// from the LocalMachine keystore and used to sign the xml document.
        /// Be sure to have appropriate permissions set on the keystore.
        /// </param>
        /// <param name="xml">
        /// XML document to be signed.
        /// </param>
        /// <param name="targetReferenceId">
        /// Reference element that will be specified as signed.
        /// </param>
        /// <param name="includePublicKey">
        /// Flag to determine whether to include the public key in the
        /// signed xml.
        /// </param>
        /// <param name="signatureMethod">Identifier of the signature method.</param>
        /// <param name="digestMethod">Identifier of the digest method.</param>
        public void SignXml(string certFriendlyName, XmlDocument xml, string targetReferenceId,
		                           bool includePublicKey, string signatureMethod, string digestMethod)
		{
			if (string.IsNullOrEmpty(certFriendlyName))
			{
				throw new Saml2Exception(Resources.SignedXmlInvalidCertFriendlyName);
			}

			if (xml == null)
			{
				throw new Saml2Exception(Resources.SignedXmlInvalidXml);
			}

			if (string.IsNullOrEmpty(targetReferenceId))
			{
				throw new Saml2Exception(Resources.SignedXmlInvalidTargetRefId);
			}

			var cert = _certificateFactory.GetCertificateByFriendlyName(certFriendlyName);
			if (cert == null)
			{
				throw new Saml2Exception(Resources.SignedXmlCertNotFound);
			}

		    using (var signingKey = cert.GetRSAPrivateKey())
		    {
		        var signedXml = new SignedXml(xml)
		        {
		            SigningKey = signingKey
		        };

		        signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
		        if (signatureMethod != null)
		        {
		            signedXml.SignedInfo.SignatureMethod = signatureMethod;
		        }

		        if (includePublicKey)
		        {
		            var keyInfo = new KeyInfo();
		            keyInfo.AddClause(new KeyInfoX509Data(cert));
		            signedXml.KeyInfo = keyInfo;
		        }

		        var reference = new Reference {Uri = "#" + targetReferenceId};

		        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
		        reference.AddTransform(new XmlDsigExcC14NTransform());
		        if (digestMethod != null)
		        {
		            reference.DigestMethod = digestMethod;
		        }

		        signedXml.AddReference(reference);
		        signedXml.ComputeSignature();

		        var xmlSignature = signedXml.GetXml();

		        var nsMgr = new XmlNamespaceManager(xml.NameTable);
		        nsMgr.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
		        nsMgr.AddNamespace("saml", Saml2Constants.NamespaceSamlAssertion);
		        nsMgr.AddNamespace("samlp", Saml2Constants.NamespaceSamlProtocol);

		        var issuerNode = TryGetNode(xml, nsMgr, "saml:Issuer");
		        if (issuerNode != null)
		        {
		            RequireRootElement(xml).InsertAfter(xmlSignature, issuerNode);
		        }
		        else
		        {
		            // Insert as a child to the target reference id
		            var targetNode = RequireNode(xml, nsMgr, "//*[@ID='" + targetReferenceId + "']");
		            targetNode.PrependChild(xmlSignature);
		        }
		    }
		}

	    /// <summary>
		/// Validates a relay state URL with a list of allowed relay states,
		/// each expected to be written as a regular expression pattern. If
		/// the list is empty, then by default all are allowed.
		/// </summary>
		/// <param name="relayState">The relay state URL to check</param>
		/// <param name="allowedRelayStates">
		/// ArrayList of allowed relay states written as a regular expression pattern
		/// </param>
		/// <exception cref="Saml2Exception">
		/// Throws Saml2Exception if a relay state is provided and does not
		/// match any of the allowed relay states.
		/// </exception>
		public void ValidateRelayState(string relayState, ArrayList allowedRelayStates)
		{
			if (string.IsNullOrEmpty(relayState) || allowedRelayStates == null || allowedRelayStates.Count == 0)
			{
				// If none specified, default to valid for backwards compatibility
				return;
			}

			var valid = false;
			foreach (string pattern in allowedRelayStates)
			{
				if (!string.IsNullOrEmpty(pattern) && Regex.IsMatch(relayState, pattern))
				{
					valid = true;
					break;
				}
			}

			if (!valid)
			{
				throw new Saml2Exception(Resources.InvalidRelayState);
			}
		}

		/// <summary>
		/// Validates a signed xml document with the given certificate,
		/// the xml signature, and the target reference id.
		/// </summary>
		/// <param name="cert">
		/// X509Certificate used to verify the signature of the xml document.
		/// </param>
		/// <param name="xmlDoc">
		/// XML document whose signature will be checked.
		/// </param>
		/// <param name="xmlSignature">Signature of the XML document.</param>
		/// <param name="targetReferenceId">
		/// Reference element that should be signed.
		/// </param>
		public void ValidateSignedXml(X509Certificate2 cert, IXPathNavigable xmlDoc, IXPathNavigable xmlSignature,
		                                     string targetReferenceId)
		{
			var signedXml = new SignedXml((XmlDocument) xmlDoc);
			signedXml.LoadXml((XmlElement) xmlSignature);

			var results = signedXml.CheckSignature(cert, true);
			if (results == false)
			{
				throw new Saml2Exception(Resources.SignedXmlCheckSignatureFailed);
			}

			var foundValidSignedReference = false;
			foreach (Reference r in signedXml.SignedInfo.References)
			{
				var referenceId = r.Uri.Substring(1);
				if (referenceId == targetReferenceId)
				{
					foundValidSignedReference = true;
				}
			}

			if (!foundValidSignedReference)
			{
				throw new Saml2Exception(Resources.SignedXmlInvalidReference);
			}
		}

		/// <summary>
		/// Validates a signed query string.
		/// </summary>
		/// <param name="cert">
		/// X509Certificate used to verify the signature of the xml document.
		/// </param>
		/// <param name="queryString">
		/// Query string to validate.  SigAlg and Signature are expected
		/// to in the set of parameters.
		/// </param>
		public void ValidateSignedQueryString(X509Certificate2 cert, string queryString)
		{
		    if (cert == null)
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringCertIsNull);
		    }

		    if (string.IsNullOrEmpty(queryString))
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringIsNull);
		    }

		    char[] queryStringSep = {'&'};
		    var queryParams = new NameValueCollection();
		    foreach (var pairs in queryString.Split(queryStringSep))
		    {
		        var key = pairs.Substring(0, pairs.IndexOf("=", StringComparison.Ordinal));
		        var value = pairs.Substring(pairs.IndexOf("=", StringComparison.Ordinal) + 1);

		        queryParams[key] = value;
		    }

		    if (string.IsNullOrEmpty(queryParams[Saml2Constants.SignatureAlgorithm]))
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringMissingSigAlg);
		    }

		    if (string.IsNullOrEmpty(queryParams[Saml2Constants.Signature]))
		    {
		        throw new Saml2Exception(Resources.SignedQueryStringMissingSignature);
		    }

		    var signatureAlgorithmUrl = HttpUtility.UrlDecode(queryParams[Saml2Constants.SignatureAlgorithm]);
		    var signature = HttpUtility.UrlDecode(queryParams[Saml2Constants.Signature]);

		    // construct a new query string with specific sequence and no signature param
		    var newQueryString = string.Empty;
		    if (!string.IsNullOrEmpty(queryParams[Saml2Constants.RequestParameter]))
		    {
		        newQueryString = Saml2Constants.RequestParameter + "=" + queryParams[Saml2Constants.RequestParameter];
		    }
		    else if (!string.IsNullOrEmpty(queryParams[Saml2Constants.ResponseParameter]))
		    {
		        newQueryString = Saml2Constants.ResponseParameter + "=" + queryParams[Saml2Constants.ResponseParameter];
		    }

		    if (!string.IsNullOrEmpty(queryParams[Saml2Constants.RelayState]))
		    {
		        newQueryString += "&" + Saml2Constants.RelayState + "=" + queryParams[Saml2Constants.RelayState];
		    }

		    newQueryString += "&" + Saml2Constants.SignatureAlgorithm + "=" + queryParams[Saml2Constants.SignatureAlgorithm];

		    var dataBuffer = Encoding.UTF8.GetBytes(newQueryString);
		    var sigBuffer = Convert.FromBase64String(signature);

		    using (var signingKey = cert.GetRSAPublicKey())
		    {
		        var publicKey = signingKey;
                var hashAlgorithmName = GetHashAlgorithmNameFromSignatureAlgorithmUrl(signatureAlgorithmUrl);
                if (!publicKey.VerifyData(dataBuffer, sigBuffer, hashAlgorithmName, RSASignaturePadding.Pkcs1))
		        {
		            throw new Saml2Exception(Resources.SignedQueryStringVerifyDataFailed);
		        }
		    }
		}

	    /// <summary>
	    /// Creates a new instance of <see cref="Saml2Utils"/>.
	    /// </summary>
	    public static Saml2Utils Create()
	    {
	        return new Saml2Utils(new FedletCertificateFactory());
	    }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static string RequireAttributeValue(XmlDocument document, XmlNamespaceManager nsmgr, string xpath,
            string attribute)
        {
            var root = RequireRootElement(document);
            var node = root.SelectSingleNode(xpath, nsmgr);
            var att = node?.Attributes?[attribute];
            if (!string.IsNullOrEmpty(att?.Value))
            {
                return att.Value.Trim();
            }
            throw new Saml2Exception($"Could not resolve attribute {xpath} at {attribute}");
        }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static string TryGetAttributeValue(XmlDocument document, XmlNamespaceManager nsmgr, string xpath,
            string attribute)
        {
            var root = RequireRootElement(document);
            var node = root.SelectSingleNode(xpath, nsmgr);
            if (node?.Attributes == null)
            {
                return null;
            }

            var att = node.Attributes[attribute];
            return string.IsNullOrEmpty(att?.Value) ? null : att.Value.Trim();
        }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static string TryGetNodeText(XmlDocument document, XmlNamespaceManager nsmgr, string xpath)
        {
            var root = RequireRootElement(document);
            var node = root.SelectSingleNode(xpath, nsmgr);
            return string.IsNullOrEmpty(node?.InnerText) ? null : node.InnerText.Trim();
        }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static string RequireNodeText(XmlDocument document, XmlNamespaceManager nsmgr, string xpath)
        {
            var root = RequireRootElement(document);
            var node = root.SelectSingleNode(xpath, nsmgr);
            var text = node?.InnerText;
            if (!string.IsNullOrEmpty(text))
            {
                return text.Trim();
            }
            throw new Saml2Exception("Could not resolve node text at " + xpath);
        }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static XmlNode TryGetNode(XmlDocument document, XmlNamespaceManager nsmgr, string xpath)
        {
            var root = RequireRootElement(document);
            return root.SelectSingleNode(xpath, nsmgr);
        }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static XmlNode RequireNode(XmlDocument document, XmlNamespaceManager nsmgr, string xpath)
        {
            var node = TryGetNode(document, nsmgr, xpath);
            if (node != null)
            {
                return node;
            }
            throw new Saml2Exception("Could not resolve node at " + xpath);
        }

        /// <summary>
        /// Xml utility.
        /// </summary>
        public static XmlNode RequireRootElement(XmlDocument xmlDocument)
        {
            var root = xmlDocument.DocumentElement;
            if (root == null)
            {
                throw new Saml2Exception("Could not resolve root element");
            }
            return root;
        }
	}
}