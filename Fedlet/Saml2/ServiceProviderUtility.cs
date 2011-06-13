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
 * $Id: ServiceProviderUtility.cs,v 1.9 2010/01/26 01:20:14 ggennaro Exp $
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Xml;
using Sun.Identity.Common;
using Sun.Identity.Properties;
using Sun.Identity.Saml2.Exceptions;

namespace Sun.Identity.Saml2
{
    /// <summary>
	/// Utility class to encapsulate configuration and metadata management
	/// along with convenience methods for retrieveing SAML2 objects.
	/// </summary>
	public class ServiceProviderUtility : IServiceProviderUtility
    {
    	private readonly IFedletRepository _repository;

    	#region Members

        private ILogger logger = LoggerFactory.GetLogger<ServiceProviderUtility>();

		#endregion


		#region Constructors

		/// <summary>
		/// Initializes a new instance of the ServiceProviderUtility class
		/// using the App_Data folder for the application as the default home
		/// folder for configuration and metadata.
		/// </summary>
		/// <param name="context">HttpContext used for reading application data.</param>
        public ServiceProviderUtility(HttpContextBase context)
			: this(context.Server.MapPath(@"App_Data"))
		{
		}

		/// <summary>
		/// Initializes a new instance of the ServiceProviderUtility class
		/// using the given home folder for configuration and metadata.
		/// </summary>
		/// <param name="homeFolder">Home folder containing configuration and metadata.</param>
		public ServiceProviderUtility(string homeFolder)
			: this(new FileWatcherFedletRepository(homeFolder))
		{
		}

		/// <summary>
		/// Initializes a new instance of the ServiceProviderUtility class
		/// using the given repository for configuration and metadata.
		/// </summary>
		/// <param name="repository">repository containing configuration and metadata.</param>
		public ServiceProviderUtility(IFedletRepository repository)
		{
			_repository = repository;
		}

    	#endregion

		#region Properties

    	/// <summary>
    	/// Gets the service provider configured for the hosted application.
    	/// </summary>
    	public IServiceProvider ServiceProvider
    	{
    		get { return _repository.GetServiceProvider(); }
    	}

    	/// <summary>
    	/// Gets the collection of identity providers configured for the
    	/// hosted application where the key is the identity provider's
    	/// entity ID.
    	/// </summary>
    	public Dictionary<string, IIdentityProvider> IdentityProviders
    	{
    		get { return _repository.GetIdentityProviders(); }
    	}

    	/// <summary>
    	/// Gets the collection of circle-of-trusts configured for the
    	/// hosted application where the key is the circle-of-trust's
    	/// "cot-name".
    	/// </summary>
    	public Dictionary<string, ICircleOfTrust> CircleOfTrusts
    	{
    		get { return _repository.GetCircleOfTrusts(); }
    	}

		#endregion

		#region Public Retrieval Methods

		/// <summary>
		/// Retrieve the ArtifactResponse object with the given SAMLv2 
		/// artifact.
		/// </summary>
		/// <param name="artifact">SAMLv2 artifact</param>
		/// <returns>ArtifactResponse object</returns>
		public ArtifactResponse GetArtifactResponse(Artifact artifact)
		{
			var artifactResolve = new ArtifactResolve(ServiceProvider, artifact);
			ArtifactResponse artifactResponse;

			IIdentityProvider idp = GetIdpFromArtifact(artifact);
			if (idp == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpNotDeterminedFromArtifact);
			}

			string artifactResolutionSvcLoc = idp.GetArtifactResolutionServiceLocation(Saml2Constants.HttpSoapProtocolBinding);
			if (artifactResolutionSvcLoc == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpArtifactResSvcLocNotDefined);
			}

			HttpWebRequest request;
			HttpWebResponse response = null;
			try
			{
				var artifactResolutionSvcUri = new Uri(artifactResolutionSvcLoc);
				request = (HttpWebRequest) WebRequest.Create(artifactResolutionSvcUri);
				var artifactResolveXml = (XmlDocument) artifactResolve.XmlDom;

				if (idp.WantArtifactResolveSigned)
				{
					if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
					{
						throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
					}
					else
					{
						Saml2Utils.SignXml(
							ServiceProvider.SigningCertificateAlias,
							artifactResolveXml,
							artifactResolve.Id,
							true);
					}
				}

				string soapMessage = Saml2Utils.CreateSoapMessage(artifactResolveXml.InnerXml);

				byte[] byteArray = Encoding.UTF8.GetBytes(soapMessage);
				request.ContentType = "text/xml";
				request.ContentLength = byteArray.Length;
				request.AllowAutoRedirect = false;
				request.Method = "POST";

				Stream requestStream = request.GetRequestStream();
				requestStream.Write(byteArray, 0, byteArray.Length);
				requestStream.Close();

                logger.Info("ArtifactResolve:\r\n{0}", artifactResolveXml.OuterXml);

				response = (HttpWebResponse) request.GetResponse();

				string responseContent = null;
				using (var responseStream = response.GetResponseStream())
				{
					if (responseStream != null)
					{
						var streamReader = new StreamReader(responseStream);
						responseContent = streamReader.ReadToEnd();
						streamReader.Close();
					}
				}

				var soapResponse = new XmlDocument();
				soapResponse.PreserveWhitespace = true;
				soapResponse.LoadXml(responseContent);

				var soapNsMgr = new XmlNamespaceManager(soapResponse.NameTable);
				soapNsMgr.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
				soapNsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
				soapNsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
				soapNsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

				XmlElement root = soapResponse.DocumentElement;
				XmlNode responseXml = root.SelectSingleNode("/soap:Envelope/soap:Body/samlp:ArtifactResponse", soapNsMgr);
				string artifactResponseXml = responseXml.OuterXml;

				artifactResponse = new ArtifactResponse(artifactResponseXml);

				if (artifactResolve.Id != artifactResponse.InResponseTo)
				{
					throw new Saml2Exception(Resources.ArtifactResolutionInvalidInResponseTo);
				}
			}
			catch (WebException we)
			{
				throw new ServiceProviderUtilityException(Resources.ArtifactResolutionWebException, we);
			}
			finally
			{
				if (response != null)
				{
					response.Close();
				}
			}

			return artifactResponse;
		}

		/// <summary>
		/// Retrieve the AuthnResponse object found within the HttpRequest
		/// in the context of the HttpContext, performing validation of
		/// the AuthnResponse prior to returning to the user.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <returns>AuthnResponse object</returns>
		public AuthnResponse GetAuthnResponse(HttpContextBase context)
		{
			ArtifactResponse artifactResponse = null;
			AuthnResponse authnResponse;
			ICollection authnRequests = AuthnRequestCache.GetSentAuthnRequests(context);
			HttpRequestBase request = context.Request;

			// Obtain AuthnResponse object from either HTTP-POST or HTTP-Artifact
			if (!string.IsNullOrWhiteSpace(request[Saml2Constants.ResponseParameter]))
			{
				string samlResponse = Saml2Utils.ConvertFromBase64(request[Saml2Constants.ResponseParameter]);
				authnResponse = new AuthnResponse(samlResponse);

				var xmlDoc = (XmlDocument) authnResponse.XmlDom;
                logger.Info("AuthnResponse:\r\n{0}", xmlDoc.OuterXml);
			}
			else if (!string.IsNullOrWhiteSpace(request[Saml2Constants.ArtifactParameter]))
			{
				var artifact = new Artifact(request[Saml2Constants.ArtifactParameter]);
				artifactResponse = GetArtifactResponse(artifact);
				authnResponse = artifactResponse.AuthnResponse;

				var xmlDoc = (XmlDocument) artifactResponse.XmlDom;
                logger.Info("ArtifactResponse:\r\n{0}", xmlDoc.OuterXml);
			}
			else
            {
                throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityNoSamlResponseReceived);
			}

			string prevAuthnRequestId = authnResponse.InResponseTo;
			try
			{
				if (artifactResponse != null)
				{
					ValidateForArtifact(artifactResponse, authnRequests);
				}
				else
				{
					ValidateForPost(authnResponse, authnRequests);
				}
			}
			catch (Saml2Exception se)
			{
				// add some context
				var authnResponseXml = (XmlDocument) authnResponse.XmlDom;
			    se.Data["xml"] = authnResponseXml.InnerXml;
				throw;
			}
			finally
			{
				AuthnRequestCache.RemoveSentAuthnRequest(context, prevAuthnRequestId);
			}

			return authnResponse;
		}

		/// <summary>
		/// Retrieve the LogoutRequest object found within the HttpRequest
		/// in the context of the HttpContext, performing validation of
		/// the LogoutRequest prior to returning to the user.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <returns>LogoutRequest object</returns>
        public LogoutRequest GetLogoutRequest(HttpContextBase context)
		{
            HttpRequestBase request = context.Request;
			string samlRequest = null;

			// Obtain the LogoutRequest object...
			if (request.HttpMethod == "GET")
			{
				samlRequest = Saml2Utils.ConvertFromBase64Decompress(request[Saml2Constants.RequestParameter]);
			}
			else if (request.HttpMethod == "POST")
			{
				// something posted...check if soap vs form post
				if (!String.IsNullOrEmpty(request[Saml2Constants.RequestParameter]))
				{
					samlRequest = Saml2Utils.ConvertFromBase64(request[Saml2Constants.RequestParameter]);
				}
				else
				{
					var reader = new StreamReader(request.InputStream);
					string requestContent = reader.ReadToEnd();

					var soapRequest = new XmlDocument();
					soapRequest.PreserveWhitespace = true;
					soapRequest.LoadXml(requestContent);

					var soapNsMgr = new XmlNamespaceManager(soapRequest.NameTable);
					soapNsMgr.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
					soapNsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
					soapNsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
					soapNsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

					XmlElement root = soapRequest.DocumentElement;
					XmlNode requestXml = root.SelectSingleNode("/soap:Envelope/soap:Body/samlp:LogoutRequest", soapNsMgr);
					samlRequest = requestXml.OuterXml;
				}
			}

			// Check if a saml request was received...
			if (samlRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityNoSamlRequestReceived);
			}

			var logoutRequest = new LogoutRequest(samlRequest);

			var xmlDoc = (XmlDocument) logoutRequest.XmlDom;
            logger.Info("LogoutRequest:\r\n{0}", xmlDoc.OuterXml);

			try
			{
				if (request.HttpMethod == "GET")
				{
					string queryString
						= request.RawUrl.Substring(request.RawUrl.IndexOf("?", StringComparison.Ordinal) + 1);
					logger.Info("LogoutRequest query string:\r\n{0}", queryString);
					ValidateForRedirect(logoutRequest, queryString);
				}
				else
				{
					ValidateForPost(logoutRequest);
				}
			}
			catch (Saml2Exception se)
            {
                // add some context
                se.Data["xml"] = xmlDoc.InnerXml;
				throw;
			}

			return logoutRequest;
		}

		/// <summary>
		/// Retrieve the LogoutResponse object found within the HttpRequest
		/// in the context of the HttpContext, performing validation of
		/// the LogoutResponse prior to returning to the user.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <returns>LogoutResponse object</returns>
        public LogoutResponse GetLogoutResponse(HttpContextBase context)
		{
			LogoutResponse logoutResponse;
            HttpRequestBase request = context.Request;

			// Check if a saml response was received...
			if (String.IsNullOrEmpty(request[Saml2Constants.ResponseParameter]))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityNoSamlResponseReceived);
			}

			// Obtain the LogoutRequest object...
			if (request.HttpMethod == "GET")
			{
				string samlResponse = Saml2Utils.ConvertFromBase64Decompress(request[Saml2Constants.ResponseParameter]);
				logoutResponse = new LogoutResponse(samlResponse);
			}
			else
			{
				string samlResponse = Saml2Utils.ConvertFromBase64(request[Saml2Constants.ResponseParameter]);
				logoutResponse = new LogoutResponse(samlResponse);
			}

			var xmlDoc = (XmlDocument) logoutResponse.XmlDom;
            logger.Info("LogoutResponse:\r\n{0}", xmlDoc.OuterXml);

			string prevLogoutRequestId = logoutResponse.InResponseTo;
			try
			{
				if (request.HttpMethod == "GET")
				{
					string queryString
						= request.RawUrl.Substring(request.RawUrl.IndexOf("?", StringComparison.Ordinal) + 1);
					logger.Info("LogoutResponse query string:\r\n{0}", queryString);
					ValidateForRedirect(logoutResponse, LogoutRequestCache.GetSentLogoutRequests(context), queryString);
				}
				else
				{
					ValidateForPost(logoutResponse, LogoutRequestCache.GetSentLogoutRequests(context));
				}
			}
			catch (Saml2Exception se)
            {
                // add some context
                se.Data["xml"] = xmlDoc.InnerXml;
				throw;
			}
			finally
			{
				LogoutRequestCache.RemoveSentLogoutRequest(context, prevLogoutRequestId);
			}

			return logoutResponse;
		}

		/// <summary>
		/// Gets the HTML for use of submitting the AuthnRequest with POST.
		/// </summary>
		/// <param name="authnRequest">
		/// AuthnRequest to packaged for a POST.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameVallueCollection of additional parameters.
		/// </param>
		/// <returns>
		/// HTML with auto-form submission with POST of the AuthnRequest
		/// </returns>
		public string GetAuthnRequestPostHtml(AuthnRequest authnRequest, string idpEntityId, NameValueCollection parameters)
		{
			if (authnRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.AuthnRequestIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			string ssoPostLocation = idp.GetSingleSignOnServiceLocation(Saml2Constants.HttpPostProtocolBinding);
			if (ssoPostLocation == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleSignOnSvcLocNotDefined);
			}

			string relayState = null;
			if (parameters != null && !string.IsNullOrEmpty(parameters[Saml2Constants.RelayState]))
			{
				relayState = parameters[Saml2Constants.RelayState];
				Saml2Utils.ValidateRelayState(relayState, ServiceProvider.RelayStateUrlList);
			}


			var authnRequestXml = (XmlDocument) authnRequest.XmlDom;
			if (ServiceProvider.AuthnRequestsSigned || idp.WantAuthnRequestsSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				Saml2Utils.SignXml(
					ServiceProvider.SigningCertificateAlias,
					authnRequestXml,
					authnRequest.Id,
					true);
				logger.Info("Signed AuthnRequest:\r\n{0}", authnRequestXml.InnerXml);
			}

			string packagedAuthnRequest = Saml2Utils.ConvertToBase64(authnRequestXml.InnerXml);
			string inputFieldFormat = "<input type=\"hidden\" name=\"{0}\" value=\"{1}\" />";

			var html = new StringBuilder();
			html.Append("<html><head><title>OpenSSO - SP initiated SSO</title></head>");
			html.Append("<body onload=\"document.forms[0].submit();\">");
			html.Append("<form method=\"post\" action=\"");
			html.Append(ssoPostLocation);
			html.Append("\">");
			html.Append("<input type=\"hidden\" name=\"");
			html.Append(Saml2Constants.RequestParameter);
			html.Append("\" value=\"");
			html.Append(packagedAuthnRequest);
			html.Append("\" />");

			if (!string.IsNullOrEmpty(relayState))
			{
				html.Append(string.Format(
					CultureInfo.InvariantCulture,
					inputFieldFormat,
					Saml2Constants.RelayState,
					HttpUtility.HtmlEncode(relayState)));
			}

			html.Append("</form>");
			html.Append("</body>");
			html.Append("</html>");

			return html.ToString();
		}

		/// <summary>
		/// Gets the AuthnRequest location along with querystring parameters 
		/// to be used for actual browser requests.
		/// </summary>
		/// <param name="authnRequest">
		/// AuthnRequest to packaged for a redirect.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameVallueCollection of additional parameters.
		/// </param>
		/// <returns>
		/// URL with query string parameter for the specified IDP.
		/// </returns>
		public string GetAuthnRequestRedirectLocation(AuthnRequest authnRequest, string idpEntityId,
		                                              NameValueCollection parameters)
		{
			if (authnRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.AuthnRequestIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			string ssoRedirectLocation = idp.GetSingleSignOnServiceLocation(Saml2Constants.HttpRedirectProtocolBinding);
			if (ssoRedirectLocation == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleSignOnSvcLocNotDefined);
			}

			string packagedAuthnRequest = Saml2Utils.CompressConvertToBase64UrlEncode(authnRequest.XmlDom);
			string queryString = Saml2Constants.RequestParameter + "=" + packagedAuthnRequest;

			if (parameters != null && !string.IsNullOrEmpty(parameters[Saml2Constants.RelayState]))
			{
				string relayState = parameters[Saml2Constants.RelayState];
				Saml2Utils.ValidateRelayState(relayState, ServiceProvider.RelayStateUrlList);
				queryString += "&" + Saml2Constants.RelayState;
				queryString += "=" + HttpUtility.UrlEncode(relayState);
			}

			if (ServiceProvider.AuthnRequestsSigned || idp.WantAuthnRequestsSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				queryString += "&" + Saml2Constants.SignatureAlgorithm;
				queryString += "=" + HttpUtility.UrlEncode(Saml2Constants.SignatureAlgorithmRsa);
				queryString = Saml2Utils.SignQueryString(ServiceProvider.SigningCertificateAlias, queryString);
			}

			var redirectUrl = new StringBuilder();
			redirectUrl.Append(ssoRedirectLocation);
			redirectUrl.Append(Saml2Utils.GetQueryStringDelimiter(ssoRedirectLocation));
			redirectUrl.Append(queryString);

			logger.Info("AuthnRequest via Redirect:\r\n{0}", redirectUrl);

			return redirectUrl.ToString();
		}

		/// <summary>
		/// Gets the HTML for use of submitting the LogoutRequest with POST.
		/// </summary>
		/// <param name="logoutRequest">
		/// LogoutRequest to packaged for a POST.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameVallueCollection of additional parameters.
		/// </param>
		/// <returns>
		/// HTML with auto-form submission with POST of the LogoutRequest
		/// </returns>
		public string GetLogoutRequestPostHtml(LogoutRequest logoutRequest, string idpEntityId, NameValueCollection parameters)
		{
			if (logoutRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityLogoutRequestIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			string sloPostLocation = idp.GetSingleLogoutServiceLocation(Saml2Constants.HttpPostProtocolBinding);
			if (sloPostLocation == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleLogoutSvcLocNotDefined);
			}

			string relayState = null;
			if (parameters != null && !string.IsNullOrEmpty(parameters[Saml2Constants.RelayState]))
			{
				relayState = parameters[Saml2Constants.RelayState];
				Saml2Utils.ValidateRelayState(relayState, ServiceProvider.RelayStateUrlList);
			}

			var logoutRequestXml = (XmlDocument) logoutRequest.XmlDom;

			if (idp.WantLogoutRequestSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				Saml2Utils.SignXml(
					ServiceProvider.SigningCertificateAlias,
					logoutRequestXml,
					logoutRequest.Id,
					true);
			}

			string packagedLogoutRequest = Saml2Utils.ConvertToBase64(logoutRequestXml.InnerXml);
			string inputFieldFormat = "<input type=\"hidden\" name=\"{0}\" value=\"{1}\" />";

			var html = new StringBuilder();
			html.Append("<html><head><title>OpenSSO - SP initiated SLO</title></head>");
			html.Append("<body onload=\"document.forms[0].submit();\">");
			html.Append("<form method=\"post\" action=\"");
			html.Append(sloPostLocation);
			html.Append("\">");
			html.Append("<input type=\"hidden\" name=\"");
			html.Append(Saml2Constants.RequestParameter);
			html.Append("\" value=\"");
			html.Append(packagedLogoutRequest);
			html.Append("\" />");

			if (!string.IsNullOrEmpty(relayState))
			{
				html.Append(string.Format(
					CultureInfo.InvariantCulture,
					inputFieldFormat,
					Saml2Constants.RelayState,
					HttpUtility.HtmlEncode(relayState)));
			}

			html.Append("</form>");
			html.Append("</body>");
			html.Append("</html>");

			return html.ToString();
		}

		/// <summary>
		/// Gets the LogoutRequest location along with querystring parameters 
		/// to be used for actual browser requests.
		/// </summary>
		/// <param name="logoutRequest">
		/// LogoutRequest to packaged for a redirect.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameVallueCollection of additional parameters.
		/// </param>
		/// <returns>
		/// URL with query string parameter for the specified IDP.
		/// </returns>
		public string GetLogoutRequestRedirectLocation(LogoutRequest logoutRequest, string idpEntityId,
		                                               NameValueCollection parameters)
		{
			if (logoutRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityLogoutRequestIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			string sloRedirectLocation = idp.GetSingleLogoutServiceLocation(Saml2Constants.HttpRedirectProtocolBinding);
			if (sloRedirectLocation == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleLogoutSvcLocNotDefined);
			}

			string packagedLogoutRequest = Saml2Utils.CompressConvertToBase64UrlEncode(logoutRequest.XmlDom);
			string queryString = Saml2Constants.RequestParameter + "=" + packagedLogoutRequest;

			if (parameters != null && !string.IsNullOrEmpty(parameters[Saml2Constants.RelayState]))
			{
				string relayState = parameters[Saml2Constants.RelayState];
				Saml2Utils.ValidateRelayState(relayState, ServiceProvider.RelayStateUrlList);
				queryString += "&" + Saml2Constants.RelayState;
				queryString += "=" + HttpUtility.UrlEncode(relayState);
			}

			if (idp.WantLogoutRequestSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				queryString += "&" + Saml2Constants.SignatureAlgorithm;
				queryString += "=" + HttpUtility.UrlEncode(Saml2Constants.SignatureAlgorithmRsa);
				queryString = Saml2Utils.SignQueryString(ServiceProvider.SigningCertificateAlias, queryString);
			}

			var redirectUrl = new StringBuilder();
			redirectUrl.Append(sloRedirectLocation);
			redirectUrl.Append(Saml2Utils.GetQueryStringDelimiter(sloRedirectLocation));
			redirectUrl.Append(queryString);

			logger.Info("LogoutRequest via Redirect:\r\n{0}", redirectUrl);

			return redirectUrl.ToString();
		}

		/// <summary>
		/// Gets the HTML for use of submitting the LogoutResponse with POST.
		/// </summary>
		/// <param name="logoutResponse">
		/// LogoutResponse to packaged for a POST.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameVallueCollection of additional parameters.
		/// </param>
		/// <returns>
		/// HTML with auto-form submission with POST of the LogoutRequest
		/// </returns>
		public string GetLogoutResponsePostHtml(LogoutResponse logoutResponse, string idpEntityId,
		                                        NameValueCollection parameters)
		{
			if (logoutResponse == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityLogoutResponseIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			string sloPostResponseLocation = idp.GetSingleLogoutServiceResponseLocation(Saml2Constants.HttpPostProtocolBinding);
			if (sloPostResponseLocation == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleLogoutSvcResLocNotDefined);
			}

			string relayState = null;
			if (parameters != null && !string.IsNullOrEmpty(parameters[Saml2Constants.RelayState]))
			{
				relayState = parameters[Saml2Constants.RelayState];
				Saml2Utils.ValidateRelayState(relayState, ServiceProvider.RelayStateUrlList);
			}

			var logoutResponseXml = (XmlDocument) logoutResponse.XmlDom;

			if (idp.WantLogoutResponseSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				Saml2Utils.SignXml(
					ServiceProvider.SigningCertificateAlias,
					logoutResponseXml,
					logoutResponse.Id,
					true);
			}

			string packagedLogoutResponse = Saml2Utils.ConvertToBase64(logoutResponseXml.InnerXml);
			string inputFieldFormat = "<input type=\"hidden\" name=\"{0}\" value=\"{1}\" />";

			var html = new StringBuilder();
			html.Append("<html><head><title>OpenSSO - IDP initiated SLO</title></head>");
			html.Append("<body onload=\"document.forms[0].submit();\">");
			html.Append("<form method=\"post\" action=\"");
			html.Append(sloPostResponseLocation);
			html.Append("\">");
			html.Append("<input type=\"hidden\" name=\"");
			html.Append(Saml2Constants.ResponseParameter);
			html.Append("\" value=\"");
			html.Append(packagedLogoutResponse);
			html.Append("\" />");

			if (!string.IsNullOrEmpty(relayState))
			{
				html.Append(string.Format(
					CultureInfo.InvariantCulture,
					inputFieldFormat,
					Saml2Constants.RelayState,
					HttpUtility.HtmlEncode(relayState)));
			}

			html.Append("</form>");
			html.Append("</body>");
			html.Append("</html>");

			return html.ToString();
		}

		/// <summary>
		/// Gets the LogoutResponse location along with querystring parameters 
		/// to be used for actual browser requests.
		/// </summary>
		/// <param name="logoutResponse">
		/// LogoutResponse to packaged for a redirect.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameVallueCollection of additional parameters.
		/// </param>
		/// <returns>
		/// URL with query string parameter for the specified IDP.
		/// </returns>
		public string GetLogoutResponseRedirectLocation(LogoutResponse logoutResponse, string idpEntityId,
		                                                NameValueCollection parameters)
		{
			if (logoutResponse == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityLogoutResponseIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			string sloRedirectResponseLocation =
				idp.GetSingleLogoutServiceResponseLocation(Saml2Constants.HttpRedirectProtocolBinding);
			if (sloRedirectResponseLocation == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleLogoutSvcLocNotDefined);
			}

			string packagedLogoutResponse = Saml2Utils.CompressConvertToBase64UrlEncode(logoutResponse.XmlDom);
			string queryString = Saml2Constants.ResponseParameter + "=" + packagedLogoutResponse;

			if (parameters != null && !string.IsNullOrEmpty(parameters[Saml2Constants.RelayState]))
			{
				string relayState = parameters[Saml2Constants.RelayState];
				Saml2Utils.ValidateRelayState(relayState, ServiceProvider.RelayStateUrlList);
				queryString += "&" + Saml2Constants.RelayState;
				queryString += "=" + HttpUtility.UrlEncode(relayState);
			}

			if (idp.WantLogoutResponseSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				queryString += "&" + Saml2Constants.SignatureAlgorithm;
				queryString += "=" + HttpUtility.UrlEncode(Saml2Constants.SignatureAlgorithmRsa);
				queryString = Saml2Utils.SignQueryString(ServiceProvider.SigningCertificateAlias, queryString);
			}

			var redirectUrl = new StringBuilder();
			redirectUrl.Append(sloRedirectResponseLocation);
			redirectUrl.Append(Saml2Utils.GetQueryStringDelimiter(sloRedirectResponseLocation));
			redirectUrl.Append(queryString);

			logger.Info("LogoutResponse via Redirect:\r\n{0}", redirectUrl);

			return redirectUrl.ToString();
		}

		#endregion

		#region Public Send Methods

		/// <summary>
		/// Sends an AuthnRequest to the specified IDP with the given 
		/// parameters.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameValueCollection of varying parameters for use in the 
		/// construction of the AuthnRequest.
		/// </param>
		public void SendAuthnRequest(HttpContextBase context, string idpEntityId, NameValueCollection parameters)
		{
			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			if (parameters == null)
			{
				parameters = new NameValueCollection();
			}

			var authnRequest = new AuthnRequest(idp, ServiceProvider, parameters);
			var xmlDoc = (XmlDocument) authnRequest.XmlDom;
            logger.Info("AuthnRequest:\r\n{0}", xmlDoc.OuterXml);

			// Add this AuthnRequest for this user for validation on AuthnResponse
			AuthnRequestCache.AddSentAuthnRequest(context, authnRequest);

			// Send with Redirect or Post based on the 'reqBinding' parameter.
			if (parameters[Saml2Constants.RequestBinding] == Saml2Constants.HttpPostProtocolBinding)
			{
				string postHtml = GetAuthnRequestPostHtml(authnRequest, idpEntityId, parameters);
				context.Response.Write(postHtml);
				context.Response.End();
			}
			else
			{
				string redirectUrl = GetAuthnRequestRedirectLocation(authnRequest, idpEntityId, parameters);
				context.Response.Redirect(redirectUrl, true);
			}
		}

		/// <summary>
		/// Sends a LogoutRequest to the specified IDP with the given 
		/// parameters.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		/// <param name="parameters">
		/// NameValueCollection of varying parameters for use in the 
		/// construction of the LogoutRequest.
		/// </param>
        public void SendLogoutRequest(HttpContextBase context, string idpEntityId, NameValueCollection parameters)
		{
			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			if (parameters == null)
			{
				parameters = new NameValueCollection();
			}

			var logoutRequest = new LogoutRequest(idp, ServiceProvider, parameters);
			var xmlDoc = (XmlDocument) logoutRequest.XmlDom;
            logger.Info("LogoutRequest:\r\n{0}", xmlDoc.OuterXml);

			// Send with Redirect, POST, or SOAP based on the 'Binding' parameter.
			if (parameters[Saml2Constants.Binding] == Saml2Constants.HttpPostProtocolBinding)
			{
				LogoutRequestCache.AddSentLogoutRequest(context, logoutRequest);
				string postHtml = GetLogoutRequestPostHtml(logoutRequest, idpEntityId, parameters);
				context.Response.Write(postHtml);
				context.Response.End();
			}
			else if (parameters[Saml2Constants.Binding] == Saml2Constants.HttpRedirectProtocolBinding)
			{
				LogoutRequestCache.AddSentLogoutRequest(context, logoutRequest);
				string redirectUrl = GetLogoutRequestRedirectLocation(logoutRequest, idpEntityId, parameters);
				context.Response.Redirect(redirectUrl, true);
			}
			else if (parameters[Saml2Constants.Binding] == Saml2Constants.HttpSoapProtocolBinding)
			{
				SendSoapLogoutRequest(logoutRequest, idpEntityId);
			}
			else
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityUnsupportedLogoutBinding);
			}
		}

		/// <summary>
		/// Sends a SOAP LogoutRequest to the specified IDP.
		/// </summary>
		/// <param name="logoutRequest">
		/// LogoutRequest object.
		/// </param>
		/// <param name="idpEntityId">Entity ID of the IDP.</param>
		public void SendSoapLogoutRequest(LogoutRequest logoutRequest, string idpEntityId)
		{
			HttpWebRequest request;
			HttpWebResponse response = null;

			if (logoutRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityLogoutRequestIsNull);
			}

			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(idpEntityId, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}
			if (idp.GetSingleLogoutServiceLocation(Saml2Constants.HttpSoapProtocolBinding) == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpSingleLogoutSvcLocNotDefined);
			}

			try
			{
				var soapLogoutSvcUri = new Uri(idp.GetSingleLogoutServiceLocation(Saml2Constants.HttpSoapProtocolBinding));
				request = (HttpWebRequest) WebRequest.Create(soapLogoutSvcUri);
				var logoutRequestXml = (XmlDocument) logoutRequest.XmlDom;

				if (idp.WantLogoutRequestSigned)
				{
					if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
					{
						throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
					}
					else
					{
						Saml2Utils.SignXml(
							ServiceProvider.SigningCertificateAlias,
							logoutRequestXml,
							logoutRequest.Id,
							true);
					}
				}

				string soapMessage = Saml2Utils.CreateSoapMessage(logoutRequestXml.InnerXml);

				byte[] byteArray = Encoding.UTF8.GetBytes(soapMessage);
				request.ContentType = "text/xml";
				request.ContentLength = byteArray.Length;
				request.AllowAutoRedirect = false;
				request.Method = "POST";

				Stream requestStream = request.GetRequestStream();
				requestStream.Write(byteArray, 0, byteArray.Length);
				requestStream.Close();

				response = (HttpWebResponse) request.GetResponse();
				var streamReader = new StreamReader(response.GetResponseStream());
				string responseContent = streamReader.ReadToEnd();
				streamReader.Close();

				var soapResponse = new XmlDocument();
				soapResponse.PreserveWhitespace = true;
				soapResponse.LoadXml(responseContent);

				var soapNsMgr = new XmlNamespaceManager(soapResponse.NameTable);
				soapNsMgr.AddNamespace("soap", "http://schemas.xmlsoap.org/soap/envelope/");
				soapNsMgr.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
				soapNsMgr.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
				soapNsMgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

				XmlElement root = soapResponse.DocumentElement;
				XmlNode responseXml = root.SelectSingleNode("/soap:Envelope/soap:Body/samlp:LogoutResponse", soapNsMgr);
				string logoutResponseXml = responseXml.OuterXml;

				LogoutResponse logoutResponse = new LogoutResponse(logoutResponseXml);
                logger.Info("LogoutResponse:\r\n{0}", logoutResponseXml);

				var logoutRequests = new ArrayList {logoutRequest};
				Validate(logoutResponse, logoutRequests);
			}
			catch (WebException we)
			{
				throw new ServiceProviderUtilityException(Resources.LogoutRequestWebException, we);
			}
			finally
			{
				if (response != null)
				{
					response.Close();
				}
			}
		}

		/// <summary>
		/// Send the SAML LogoutResponse message based on the received
		/// LogoutRequest.  POST (default) or Redirect is supported.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <param name="logoutRequest">
		/// LogoutRequest corresponding to the ensuing LogoutResponse to send.
		/// </param>
        public void SendLogoutResponse(HttpContextBase context, LogoutRequest logoutRequest)
		{
			if (logoutRequest == null)
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityLogoutRequestIsNull);
			}
			
			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(logoutRequest.Issuer, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdpNotDeterminedFromLogoutRequest);
			}

			// send logout response based on how it was received
			if (context.Request.HttpMethod == "GET")
			{
				var parameters = new NameValueCollection();
				parameters[Saml2Constants.Binding] = Saml2Constants.HttpRedirectProtocolBinding;
				var logoutResponse = new LogoutResponse(idp, ServiceProvider, logoutRequest, parameters);

				var xmlDoc = (XmlDocument) logoutResponse.XmlDom;
                logger.Info("LogoutResponse:\r\n{0}", xmlDoc.OuterXml);

				parameters = Saml2Utils.GetRequestParameters(context.Request);
				string redirectUrl = GetLogoutResponseRedirectLocation(logoutResponse, idp.EntityId, parameters);
				context.Response.Redirect(redirectUrl, true);
			}
			else
			{
				var parameters = new NameValueCollection();
				parameters[Saml2Constants.Binding] = Saml2Constants.HttpPostProtocolBinding;
				var logoutResponse = new LogoutResponse(idp, ServiceProvider, logoutRequest, parameters);

				var xmlDoc = (XmlDocument) logoutResponse.XmlDom;
                logger.Info("LogoutResponse:\r\n{0}", xmlDoc.OuterXml);

				parameters = Saml2Utils.GetRequestParameters(context.Request);
				string postHtml = GetLogoutResponsePostHtml(logoutResponse, idp.EntityId, parameters);
				context.Response.Write(postHtml);
				context.Response.End();
			}
		}

		/// <summary>
		/// Writes a SOAP LogoutResponse to the Response object found within
		/// the given HttpContext based on the given logout request.
		/// </summary>
		/// <param name="context">
		/// HttpContext containing session, request, and response objects.
		/// </param>
		/// <param name="logoutRequest">
		/// LogoutRequest object.
		/// </param>
        public void SendSoapLogoutResponse(HttpContextBase context, LogoutRequest logoutRequest)
		{
			IIdentityProvider idp;
			if (!IdentityProviders.TryGetValue(logoutRequest.Issuer, out idp))
			{
				throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilityIdentityProviderNotFound);
			}

			var parameters = new NameValueCollection();
			parameters[Saml2Constants.Binding] = Saml2Constants.HttpSoapProtocolBinding;

			var logoutResponse = new LogoutResponse(idp, ServiceProvider, logoutRequest, parameters);
			var logoutResponseXml = (XmlDocument) logoutResponse.XmlDom;

			if (idp.WantLogoutResponseSigned)
			{
				if (string.IsNullOrEmpty(ServiceProvider.SigningCertificateAlias))
				{
					throw new ServiceProviderUtilityException(Resources.ServiceProviderUtilitySignFailedNoCertAlias);
				}
				
				Saml2Utils.SignXml(
					ServiceProvider.SigningCertificateAlias,
					logoutResponseXml,
					logoutResponse.Id,
					true);
			}

			logger.Info("LogoutResponse:\r\n{0}", logoutResponseXml.OuterXml);

			string soapMessage = Saml2Utils.CreateSoapMessage(logoutResponseXml.OuterXml);

			context.Response.ContentType = "text/xml";
			context.Response.Write(soapMessage);
		}

		#endregion

		#region Public Validation Methods

		/// <summary>
		/// Validates the given ArtifactResponse object.
		/// </summary>
		/// <param name="artifactResponse">ArtifactResponse object.</param>
		/// <param name="authnRequests">
		/// Collection of previously sent authnRequests used to compare with
		/// the InResponseTo attribute (if present) of the embedded 
		/// AuthnResponse within the ArtifactResponse.
		/// </param>
		/// <see cref="ServiceProviderUtility.Validate(AuthnResponse, ICollection)"/>
		public void ValidateForArtifact(ArtifactResponse artifactResponse, ICollection authnRequests)
		{
			CheckSignature(artifactResponse);
			Validate(artifactResponse.AuthnResponse, authnRequests);
		}

		/// <summary>
		/// Validates the given AuthnResponse object.
		/// </summary>
		/// <param name="authnResponse">AuthnResponse object.</param>
		/// <param name="authnRequests">
		/// Collection of previously sent authnRequests used to compare with
		/// the InResponseTo attribute (if present) of the AuthnResponse.
		/// </param>
		/// <see cref="ServiceProviderUtility.Validate(AuthnResponse, ICollection)"/>
		public void ValidateForPost(AuthnResponse authnResponse, ICollection authnRequests)
		{
			CheckSignature(authnResponse);
			Validate(authnResponse, authnRequests);
		}

		/// <summary>
		/// Validates the given LogoutRequest.
		/// </summary>
		/// <param name="logoutRequest">LogoutRequest object.</param>
		public void ValidateForPost(LogoutRequest logoutRequest)
		{
			CheckIssuer(logoutRequest.Issuer);

			if (ServiceProvider.WantLogoutRequestSigned)
			{
				CheckSignature(logoutRequest);
			}
		}

		/// <summary>
		/// Validates the given LogoutRequest.
		/// </summary>
		/// <param name="logoutRequest">LogoutRequest object.</param>
		/// <param name="queryString">
		/// Raw query string that contains the request and possible signature
		/// </param>
		public void ValidateForRedirect(LogoutRequest logoutRequest, string queryString)
		{
			CheckIssuer(logoutRequest.Issuer);

			if (ServiceProvider.WantLogoutRequestSigned)
			{
				CheckSignature(logoutRequest, queryString);
			}
		}

		/// <summary>
		/// Validates the given LogoutResponse object obtained from a POST. If
		/// this service provider desires the logout respone to be signed, XML
		/// signature checking will be performed.
		/// </summary>
		/// <param name="logoutResponse">LogoutResponse object.</param>
		/// <param name="logoutRequests">
		/// Collection of previously sent logoutRequests used to compare with
		/// the InResponseTo attribute of the LogoutResponse (if present).
		/// </param>
		public void ValidateForPost(LogoutResponse logoutResponse, ICollection logoutRequests)
		{
			if (logoutResponse == null)
			{
				throw new Saml2Exception(Resources.ServiceProviderUtilityLogoutResponseIsNull);
			}

			if (ServiceProvider.WantLogoutResponseSigned)
			{
				CheckSignature(logoutResponse);
			}

			Validate(logoutResponse, logoutRequests);
		}

		/// <summary>
		/// Validates the given LogoutResponse object obtained from a
		/// Redirect. If this service provider desires the logout respone to 
		/// be signed, XML signature checking will be performed.
		/// </summary>
		/// <param name="logoutResponse">LogoutResponse object.</param>
		/// <param name="logoutRequests">
		/// Collection of previously sent logoutRequests used to compare with
		/// the InResponseTo attribute of the LogoutResponse (if present).
		/// </param>
		/// <param name="queryString">
		/// Raw query string that contains the request and possible signature
		/// </param>
		public void ValidateForRedirect(LogoutResponse logoutResponse, ICollection logoutRequests, string queryString)
		{
			if (logoutResponse == null)
			{
				throw new Saml2Exception(Resources.ServiceProviderUtilityLogoutResponseIsNull);
			}

			if (ServiceProvider.WantLogoutResponseSigned)
			{
				CheckSignature(logoutResponse, queryString);
			}

			Validate(logoutResponse, logoutRequests);
		}

		#endregion

		#region Static Private Methods

		/// <summary>
		/// Checks the time condition of the given AuthnResponse.
		/// </summary>
		/// <param name="authnResponse">SAMLv2 AuthnResponse.</param>
		private static void CheckConditionWithTime(AuthnResponse authnResponse)
		{
			DateTime utcNow = DateTime.UtcNow;
			DateTime utcBefore = TimeZoneInfo.ConvertTimeToUtc(authnResponse.ConditionNotBefore);
			DateTime utcOnOrAfter = TimeZoneInfo.ConvertTimeToUtc(authnResponse.ConditionNotOnOrAfter);

			if (utcNow < utcBefore || utcNow >= utcOnOrAfter)
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidConditionTime);
			}
		}

		/// <summary>
		/// Checks the InResponseTo field of the given AuthnResponse to
		/// see if it is one of the managed authn requests.
		/// </summary>
		/// <param name="authnResponse">SAMLv2 AuthnResponse.</param>
		/// <param name="authnRequests">
		/// Collection of previously sent AuthnRequests.
		/// </param>
		private static void CheckInResponseTo(AuthnResponse authnResponse, ICollection authnRequests)
		{
			if (authnRequests != null && authnResponse.InResponseTo != null)
			{
				IEnumerator i = authnRequests.GetEnumerator();
				while (i.MoveNext())
				{
					var authnRequest = (AuthnRequest) i.Current;
					if (authnRequest.Id == authnResponse.InResponseTo)
					{
						// Found one, return quietly.
						return;
					}
				}
			}

			// Didn't find one, complain loudly.
			throw new Saml2Exception(Resources.AuthnResponseInvalidInResponseTo);
		}

		/// <summary>
		/// Checks the InResponseTo field of the given LogoutResponse to
		/// see if it is one of the managed logout requests.
		/// </summary>
		/// <param name="logoutResponse">SAMLv2 LogoutResponse.</param>
		/// <param name="logoutRequests">
		/// Collection of previously sent LogoutRequests.
		/// </param>
		private static void CheckInResponseTo(LogoutResponse logoutResponse, ICollection logoutRequests)
		{
			if (logoutRequests != null && logoutResponse.InResponseTo != null)
			{
				IEnumerator i = logoutRequests.GetEnumerator();
				while (i.MoveNext())
				{
					var logoutRequest = (LogoutRequest) i.Current;
					if (logoutRequest.Id == logoutResponse.InResponseTo)
					{
						// Found one, return quietly.
						return;
					}
				}
			}

			// Didn't find one, complain loudly.
			throw new Saml2Exception(Resources.LogoutResponseInvalidInResponseTo);
		}

		/// <summary>
		/// Checks for a SAML "success" status code in a SAML message, 
		/// otherwise a Saml2Exception is thrown.
		/// </summary>
		/// <param name="statusCode">StatusCode to check</param>
		private static void CheckStatusCode(string statusCode)
		{
			if (string.IsNullOrEmpty(statusCode) || statusCode != Saml2Constants.Success)
			{
				throw new Saml2Exception(Resources.InvalidStatusCode);
			}
		}

		#endregion

		#region Non-static Private Methods

		/// <summary>
		/// Checks if the provided entity ID matches one of the known entity
		/// Identity Provider ID's, otherwise a Saml2Exception is thrown..
		/// </summary>
		/// <param name="idpEntityId">IDP entity ID</param>
		private void CheckIssuer(string idpEntityId)
		{
			if (string.IsNullOrEmpty(idpEntityId) || !IdentityProviders.ContainsKey(idpEntityId))
			{
				throw new Saml2Exception(Resources.InvalidIssuer);
			}
		}

		/// <summary>
		/// Checks the audience condition of the given AuthnResponse.
		/// </summary>
		/// <param name="authnResponse">SAMLv2 AuthnResponse.</param>
		private void CheckConditionWithAudience(AuthnResponse authnResponse)
		{
			if (!authnResponse.ConditionAudiences.Contains(ServiceProvider.EntityId))
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidConditionAudience);
			}
		}

		/// <summary>
		/// Checks the signature of the given ArtifactResponse and embedded
		/// AuthnResponse used for the Artifact profile.
		/// </summary>
		/// <param name="artifactResponse">ArtifactResponse object.</param>
		/// <seealso cref="ServiceProviderUtility.ValidateForArtifact"/>
		private void CheckSignature(ArtifactResponse artifactResponse)
		{
			AuthnResponse authnResponse = artifactResponse.AuthnResponse;

			IIdentityProvider identityProvider;
			if (!IdentityProviders.TryGetValue(authnResponse.Issuer, out identityProvider))
			{
				throw new Saml2Exception(Resources.InvalidIssuer);
			}

			var artifactResponseSignature = (XmlElement) artifactResponse.XmlSignature;
			var responseSignature = (XmlElement) authnResponse.XmlResponseSignature;
			var assertionSignature = (XmlElement) authnResponse.XmlAssertionSignature;

			XmlElement validationSignature;
			string validationSignatureCert;
			string validationReferenceId;

			if (ServiceProvider.WantArtifactResponseSigned && artifactResponseSignature == null)
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureMissingOnArtifactResponse);
			}
			if (ServiceProvider.WantPostResponseSigned && responseSignature == null && artifactResponseSignature == null)
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureMissingOnResponse);
			}
			if (ServiceProvider.WantAssertionsSigned && assertionSignature == null && responseSignature == null &&
			    artifactResponseSignature == null)
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureMissing);
			}

			// pick the ArtifactResponse, Response or the Assertion for further validation...
			if (artifactResponseSignature != null)
			{
				validationSignature = artifactResponseSignature;
				validationSignatureCert = artifactResponse.SignatureCertificate;
				validationReferenceId = artifactResponse.Id;
			}
			else if (responseSignature != null)
			{
				validationSignature = responseSignature;
				validationSignatureCert = authnResponse.ResponseSignatureCertificate;
				validationReferenceId = authnResponse.Id;
			}
			else
			{
				validationSignature = assertionSignature;
				validationSignatureCert = authnResponse.AssertionSignatureCertificate;
				validationReferenceId = authnResponse.AssertionId;
			}

			if (validationSignatureCert != null)
			{
				string idpCert = Regex.Replace(identityProvider.EncodedSigningCertificate, @"\s", string.Empty);
				validationSignatureCert = Regex.Replace(validationSignatureCert, @"\s", string.Empty);
				if (idpCert != validationSignatureCert)
				{
					throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureCertsDontMatch);
				}
			}

			// check the signature of the xml document (optional for artifact)
			if (validationSignature != null)
			{
				Saml2Utils.ValidateSignedXml(
					identityProvider.SigningCertificate,
					artifactResponse.XmlDom,
					validationSignature,
					validationReferenceId);
			}
		}

		/// <summary>
		/// Checks the signature of the given AuthnResponse used for the POST
		/// profile.
		/// </summary>
		/// <param name="authnResponse">AuthnResponse object.</param>
		/// <seealso cref="ServiceProviderUtility.ValidateForPost(AuthnResponse, ICollection)"/>
		private void CheckSignature(AuthnResponse authnResponse)
		{
			IIdentityProvider identityProvider;
			if (!IdentityProviders.TryGetValue(authnResponse.Issuer, out identityProvider))
			{
				throw new Saml2Exception(Resources.InvalidIssuer);
			}

			var responseSignature = (XmlElement) authnResponse.XmlResponseSignature;
			var assertionSignature = (XmlElement) authnResponse.XmlAssertionSignature;
			XmlElement validationSignature;
			string validationSignatureCert;
			string validationReferenceId;

			if (responseSignature == null && assertionSignature == null)
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureMissing);
			}
			if (ServiceProvider.WantPostResponseSigned && responseSignature == null)
			{
				throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureMissingOnResponse);
			}

			// pick the Response or the Assertion for further validation...
			if (responseSignature != null)
			{
				validationSignature = responseSignature;
				validationSignatureCert = authnResponse.ResponseSignatureCertificate;
				validationReferenceId = authnResponse.Id;
			}
			else
			{
				validationSignature = assertionSignature;
				validationSignatureCert = authnResponse.AssertionSignatureCertificate;
				validationReferenceId = authnResponse.AssertionId;
			}

			if (validationSignatureCert != null)
			{
				string idpCert = Regex.Replace(identityProvider.EncodedSigningCertificate, @"\s", string.Empty);
				validationSignatureCert = Regex.Replace(validationSignatureCert, @"\s", string.Empty);
				if (idpCert != validationSignatureCert)
				{
					throw new Saml2Exception(Resources.AuthnResponseInvalidSignatureCertsDontMatch);
				}
			}

			// check the signature of the xml document (always for post)
			Saml2Utils.ValidateSignedXml(
				identityProvider.SigningCertificate,
				authnResponse.XmlDom,
				validationSignature,
				validationReferenceId);
		}

		/// <summary>
		/// Checks the signature of the given LogoutRequest assuming
		/// the signature is within the XML.
		/// </summary>
		/// <param name="logoutRequest">SAMLv2 LogoutRequest object.</param>
		private void CheckSignature(LogoutRequest logoutRequest)
		{
			IIdentityProvider idp;

			if (!IdentityProviders.TryGetValue(logoutRequest.Issuer, out idp))
			{
				throw new Saml2Exception(Resources.InvalidIssuer);
			}

			Saml2Utils.ValidateSignedXml(
				idp.SigningCertificate,
				logoutRequest.XmlDom,
				logoutRequest.XmlSignature,
				logoutRequest.Id);
		}

		/// <summary>
		/// Checks the signature of the given LogoutRequest with
		/// the raw query string.
		/// </summary>
		/// <param name="logoutRequest">SAMLv2 LogoutRequest object.</param>
		/// <param name="queryString">
		/// Raw query string that contains the request and possible signature.
		/// </param>
		private void CheckSignature(LogoutRequest logoutRequest, string queryString)
		{
			IIdentityProvider idp;

			if (!IdentityProviders.TryGetValue(logoutRequest.Issuer, out idp))
			{
				throw new Saml2Exception(Resources.InvalidIssuer);
			}

			Saml2Utils.ValidateSignedQueryString(idp.SigningCertificate, queryString);
		}

		/// <summary>
		/// Checks the signature of the given logoutResponse assuming
		/// the signature is within the XML.
		/// </summary>
		/// <param name="logoutResponse">SAMLv2 LogoutRequest object.</param>
		private void CheckSignature(LogoutResponse logoutResponse)
		{
			IIdentityProvider idp;

			if (!IdentityProviders.TryGetValue(logoutResponse.Issuer, out idp))
			{
				throw new Saml2Exception(Resources.InvalidIssuer);
			}

			Saml2Utils.ValidateSignedXml(
				idp.SigningCertificate,
				logoutResponse.XmlDom,
				logoutResponse.XmlSignature,
				logoutResponse.Id);
		}

		/// <summary>
		/// Checks the signature of the given LogoutResponse with
		/// the raw query string.
		/// </summary>
		/// <param name="logoutResponse">SAMLv2 LogoutResponse object.</param>
		/// <param name="queryString">
		/// Raw query string that contains the response and possible signature.
		/// </param>
		private void CheckSignature(LogoutResponse logoutResponse, string queryString)
		{
			var idp = IdentityProviders[logoutResponse.Issuer];

			Saml2Utils.ValidateSignedQueryString(idp.SigningCertificate, queryString);
		}

		/// <summary>
		/// Checks to confirm the issuer and hosted service provider are in
		/// the same circle of trust, otherwise a Saml2Exception is thrown.
		/// </summary>
		/// <param name="idpEntityId">IDP entity ID</param>
		private void CheckCircleOfTrust(string idpEntityId)
		{
			string spEntityId = ServiceProvider.EntityId;

			if (!CircleOfTrusts.Values
				.Any(cot => cot.AreProvidersTrusted(spEntityId, idpEntityId)))
			{
				throw new Saml2Exception(Resources.InvalidIdpEntityIdNotInCircleOfTrust);
			}
		}

		/// <summary>
		/// Gets the Identity Provider associated with the specified artifact.
		/// The currently maintained list of IDPs each have their entity ID
		/// hashed and compared with the given artifact's source ID to make
		/// the correct determination.
		/// </summary>
		/// <param name="artifact">SAML artifact.</param>
		/// <returns>
		/// Identity Provider who's entity ID matches the source ID
		/// within the artifact, null if not found.
		/// </returns>
		private IIdentityProvider GetIdpFromArtifact(Artifact artifact)
		{
			SHA1 sha1 = new SHA1CryptoServiceProvider();
			IIdentityProvider idp = null;
			string idpEntityIdHashed;

			foreach (string idpEntityId in IdentityProviders.Keys)
			{
				idpEntityIdHashed = BitConverter.ToString(sha1.ComputeHash(Encoding.UTF8.GetBytes(idpEntityId)));
				idpEntityIdHashed = idpEntityIdHashed.Replace("-", string.Empty);

				if (idpEntityIdHashed == artifact.SourceId)
				{
					idp = IdentityProviders[idpEntityId];
					break;
				}
			}

			return idp;
		}

		/// <summary>
		/// Validates the given AuthnResponse object except for xml signature.
		/// XML signature checking is expected to be done prior to calling
		/// this method based on the appropriate profile.
		/// </summary>
		/// <param name="authnResponse">AuthnResponse object.</param>
		/// <param name="authnRequests">
		/// Collection of previously sent authnRequests used to compare with
		/// the InResponseTo attribute of the AuthnResponse (if present).
		/// </param>
		/// <see cref="ServiceProviderUtility.ValidateForArtifact"/>
		/// <see cref="ServiceProviderUtility.ValidateForPost(AuthnResponse, ICollection)"/>
		private void Validate(AuthnResponse authnResponse, ICollection authnRequests)
		{
			if (authnResponse.InResponseTo != null)
			{
				CheckInResponseTo(authnResponse, authnRequests);
			}

			CheckIssuer(authnResponse.Issuer);
			CheckStatusCode(authnResponse.StatusCode);
			CheckConditionWithTime(authnResponse);
			CheckConditionWithAudience(authnResponse);
			CheckCircleOfTrust(authnResponse.Issuer);
		}

		/// <summary>
		/// Validates the given LogoutResponse object except for xml signature.
		/// XML signature checking is expected to be done prior to calling
		/// this method based on the appropriate profile.
		/// </summary>
		/// <param name="logoutResponse">LogoutResponse object.</param>
		/// <param name="logoutRequests">
		/// Collection of previously sent logoutRequests used to compare with
		/// the InResponseTo attribute of the LogoutResponse (if present).
		/// </param>
		private void Validate(LogoutResponse logoutResponse, ICollection logoutRequests)
		{
			if (logoutResponse == null)
			{
				throw new Saml2Exception(Resources.ServiceProviderUtilityLogoutResponseIsNull);
			}

			CheckInResponseTo(logoutResponse, logoutRequests);
			CheckIssuer(logoutResponse.Issuer);
			CheckCircleOfTrust(logoutResponse.Issuer);
			CheckStatusCode(logoutResponse.StatusCode);
		}

		#endregion
	}
}