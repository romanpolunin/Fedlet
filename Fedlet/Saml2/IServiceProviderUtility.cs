using System.Collections.Generic;
using System.Collections.Specialized;
using Microsoft.AspNetCore.Http;

namespace Sun.Identity.Saml2
{
    /// <summary>
    /// Utility class to encapsulate configuration and metadata management
    /// along with convenience methods for retrieveing SAML2 objects.
    /// </summary>
    public interface IServiceProviderUtility
    {
        /// <summary>
        /// Gets the service provider configured for the hosted application.
        /// </summary>
        IServiceProvider ServiceProvider { get; }

        /// <summary>
        /// Gets the collection of identity providers configured for the
        /// hosted application where the key is the identity provider's
        /// entity ID.
        /// </summary>
        Dictionary<string, IIdentityProvider> IdentityProviders { get; }

        /// <summary>
        /// Gets the collection of circle-of-trusts configured for the
        /// hosted application where the key is the circle-of-trust's
        /// "cot-name".
        /// </summary>
        Dictionary<string, ICircleOfTrust> CircleOfTrusts { get; }

        /// <summary>
        /// Retrieve the ArtifactResponse object with the given SAMLv2
        /// artifact.
        /// </summary>
        /// <param name="artifact">SAMLv2 artifact</param>
        /// <returns>ArtifactResponse object</returns>
        ArtifactResponse GetArtifactResponse(Artifact artifact);

        /// <summary>
        /// Retrieve the AuthnResponse object found within the HttpRequest
        /// in the context of the HttpContext, performing validation of
        /// the AuthnResponse prior to returning to the user.
        /// </summary>
        /// <param name="context">
        /// HttpContext containing session, request, and response objects.
        /// </param>
        /// <returns>AuthnResponse object</returns>
        AuthnResponse GetAuthnResponse(HttpContext context);

        /// <summary>
        /// Retrieve the LogoutRequest object found within the HttpRequest
        /// in the context of the HttpContext, performing validation of
        /// the LogoutRequest prior to returning to the user.
        /// </summary>
        /// <param name="context">
        /// HttpContext containing session, request, and response objects.
        /// </param>
        /// <returns>LogoutRequest object</returns>
        LogoutRequest GetLogoutRequest(HttpContext context);

        /// <summary>
        /// Retrieve the LogoutResponse object found within the HttpRequest
        /// in the context of the HttpContext, performing validation of
        /// the LogoutResponse prior to returning to the user.
        /// </summary>
        /// <param name="context">
        /// HttpContext containing session, request, and response objects.
        /// </param>
        /// <returns>LogoutResponse object</returns>
        LogoutResponse GetLogoutResponse(HttpContext context);

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
        string GetAuthnRequestPostHtml(AuthnRequest authnRequest, string idpEntityId, NameValueCollection parameters);

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
        string GetAuthnRequestRedirectLocation(AuthnRequest authnRequest, string idpEntityId,
                                               NameValueCollection parameters);

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
        string GetLogoutRequestPostHtml(LogoutRequest logoutRequest, string idpEntityId, NameValueCollection parameters);

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
        string GetLogoutRequestRedirectLocation(LogoutRequest logoutRequest, string idpEntityId,
                                                NameValueCollection parameters);

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
        string GetLogoutResponsePostHtml(LogoutResponse logoutResponse, string idpEntityId,
                                         NameValueCollection parameters);

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
        string GetLogoutResponseRedirectLocation(LogoutResponse logoutResponse, string idpEntityId,
                                                 NameValueCollection parameters);

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
        void SendAuthnRequest(HttpContext context, string idpEntityId, NameValueCollection parameters);

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
        void SendLogoutRequest(HttpContext context, string idpEntityId, NameValueCollection parameters);

        /// <summary>
        /// Sends a SOAP LogoutRequest to the specified IDP.
        /// </summary>
        /// <param name="logoutRequest">
        /// LogoutRequest object.
        /// </param>
        /// <param name="idpEntityId">Entity ID of the IDP.</param>
        void SendSoapLogoutRequest(LogoutRequest logoutRequest, string idpEntityId);

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
        void SendLogoutResponse(HttpContext context, LogoutRequest logoutRequest);

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
        void SendSoapLogoutResponse(HttpContext context, LogoutRequest logoutRequest);

        /// <summary>
        /// Validates the given ArtifactResponse object.
        /// </summary>
        /// <param name="artifactResponse">ArtifactResponse object.</param>
        /// <see cref="ServiceProviderUtility.Validate(AuthnResponse)"/>
        void ValidateForArtifact(ArtifactResponse artifactResponse);

        /// <summary>
        /// Validates the given AuthnResponse object.
        /// </summary>
        /// <param name="authnResponse">AuthnResponse object.</param>
        /// <see cref="ServiceProviderUtility.Validate(AuthnResponse)"/>
        void ValidateForPost(AuthnResponse authnResponse);

        /// <summary>
        /// Validates the given LogoutRequest.
        /// </summary>
        /// <param name="logoutRequest">LogoutRequest object.</param>
        void ValidateForPost(LogoutRequest logoutRequest);

        /// <summary>
        /// Validates the given LogoutRequest.
        /// </summary>
        /// <param name="logoutRequest">LogoutRequest object.</param>
        /// <param name="queryString">
        /// Raw query string that contains the request and possible signature
        /// </param>
        void ValidateForRedirect(LogoutRequest logoutRequest, string queryString);

        /// <summary>
        /// Validates the given LogoutResponse object obtained from a POST. If
        /// this service provider desires the logout respone to be signed, XML
        /// signature checking will be performed.
        /// </summary>
        /// <param name="logoutResponse">LogoutResponse object.</param>
        void ValidateForPost(LogoutResponse logoutResponse);

        /// <summary>
        /// Validates the given LogoutResponse object obtained from a
        /// Redirect. If this service provider desires the logout respone to
        /// be signed, XML signature checking will be performed.
        /// </summary>
        /// <param name="logoutResponse">LogoutResponse object.</param>
        /// <param name="queryString">
        /// Raw query string that contains the request and possible signature
        /// </param>
        void ValidateForRedirect(LogoutResponse logoutResponse, string queryString);
    }
}