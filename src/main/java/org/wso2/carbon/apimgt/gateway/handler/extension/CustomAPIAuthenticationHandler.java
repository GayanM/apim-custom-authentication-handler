package org.wso2.carbon.apimgt.gateway.handler.extension;

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.RESTConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityConstants;
import org.wso2.carbon.apimgt.gateway.handlers.security.APISecurityException;
import org.wso2.carbon.apimgt.gateway.handlers.security.Authenticator;
import org.wso2.carbon.apimgt.gateway.handlers.security.authenticator.MutualSSLAuthenticator;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.tracing.TracingSpan;
import org.wso2.carbon.apimgt.tracing.TracingTracer;
import org.wso2.carbon.apimgt.tracing.Util;
import org.wso2.carbon.metrics.manager.Timer;

import java.util.Date;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;


public class CustomAPIAuthenticationHandler extends APIAuthenticationHandler {

    private static final Log log = LogFactory.getLog(CustomAPIAuthenticationHandler.class);
    private volatile Authenticator authenticator;

    protected Authenticator getAuthenticator() {
        authenticator = super.getAuthenticator();
        if (authenticator instanceof MutualSSLAuthenticator) {
            authenticator = new CustomMutualSSLAuthenticator(getAPILevelPolicy(), getCertificateInformation());
        }
        return authenticator;
    }

    public boolean handleRequest(MessageContext messageContext) {
        TracingSpan keySpan = null;
        if (Util.tracingEnabled()) {
            TracingSpan responseLatencySpan =
                    (TracingSpan) messageContext.getProperty(APIMgtGatewayConstants.RESPONSE_LATENCY);
            TracingTracer tracer = Util.getGlobalTracer();
            keySpan = Util.startSpan(APIMgtGatewayConstants.KEY_VALIDATION, responseLatencySpan, tracer);
            messageContext.setProperty(APIMgtGatewayConstants.KEY_VALIDATION, keySpan);
            org.apache.axis2.context.MessageContext axis2MC =
                    ((Axis2MessageContext) messageContext).getAxis2MessageContext();
            axis2MC.setProperty(APIMgtGatewayConstants.KEY_VALIDATION, keySpan);
        }

        Timer.Context context = startMetricTimer();
        long startTime = System.nanoTime();
        long endTime;
        long difference;

        try {
            if (isAnalyticsEnabled()) {
                long currentTime = System.currentTimeMillis();
                messageContext.setProperty("api.ut.requestTime", Long.toString(currentTime));
            }
            if (authenticator == null) {
                initializeAuthenticator();
            }
            if (isAuthenticate(messageContext)) {
                setAPIParametersToMessageContext(messageContext);
                return true;
            }
        } catch (APISecurityException e) {

            if (Util.tracingEnabled() && keySpan != null) {
                Util.setTag(keySpan, APIMgtGatewayConstants.ERROR, APIMgtGatewayConstants.KEY_SPAN_ERROR);
            }
            if (log.isDebugEnabled()) {
                // We do the calculations only if the debug logs are enabled. Otherwise this would be an overhead
                // to all the gateway calls that is happening.
                endTime = System.nanoTime();
                difference = (endTime - startTime) / 1000000;
                String messageDetails = logMessageDetails(messageContext);
                log.debug("Call to Key Manager : " + messageDetails + ", elapsedTimeInMilliseconds=" +
                        difference / 1000000);
            }

            String errorMessage = APISecurityConstants.getAuthenticationFailureMessage(e.getErrorCode());

            if (APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE.equals(errorMessage)) {
                log.error("API authentication failure due to "
                        + APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE, e);
            } else {
                // We do not need to log known authentication failures as errors since these are not product errors.
                log.warn("API authentication failure due to " + errorMessage);

                if (log.isDebugEnabled()) {
                    log.debug("API authentication failed with error " + e.getErrorCode(), e);
                }
            }

            handleAuthFailure(messageContext, e);
        } finally {
            if (Util.tracingEnabled()) {
                Util.finishSpan(keySpan);
            }
            messageContext.setProperty(APIMgtGatewayConstants.SECURITY_LATENCY,
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime));
            stopMetricTimer(context);

        }
        return false;
    }

    protected boolean isAuthenticate(MessageContext messageContext) throws APISecurityException {
        return authenticator.authenticate(messageContext);
    }

    private String logMessageDetails(MessageContext messageContext) {
        //TODO: Hardcoded const should be moved to a common place which is visible to org.wso2.carbon.apimgt.gateway.handlers
        String applicationName = (String) messageContext.getProperty(APIMgtGatewayConstants.APPLICATION_NAME);
        String endUserName = (String) messageContext.getProperty(APIMgtGatewayConstants.END_USER_NAME);
        Date incomingReqTime = null;
        org.apache.axis2.context.MessageContext axisMC = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        String logMessage = "API call failed reason=API_authentication_failure"; //"app-name=" + applicationName + " " + "user-name=" + endUserName;
        String logID = axisMC.getOptions().getMessageId();
        if (applicationName != null) {
            logMessage = " belonging to appName=" + applicationName;
        }
        if (endUserName != null) {
            logMessage = logMessage + " userName=" + endUserName;
        }
        if (logID != null) {
            logMessage = logMessage + " transactionId=" + logID;
        }
        String userAgent = (String) ((TreeMap) axisMC.getProperty(org.apache.axis2.context.MessageContext
                .TRANSPORT_HEADERS)).get(APIConstants.USER_AGENT);
        if (userAgent != null) {
            logMessage = logMessage + " with userAgent=" + userAgent;
        }
        String accessToken = (String) ((TreeMap) axisMC.getProperty(org.apache.axis2.context.MessageContext
                .TRANSPORT_HEADERS)).get(APIMgtGatewayConstants.AUTHORIZATION);
        if (accessToken != null) {
            logMessage = logMessage + " with accessToken=" + accessToken;
        }
        String requestURI = (String) messageContext.getProperty(RESTConstants.REST_FULL_REQUEST_PATH);
        if (requestURI != null) {
            logMessage = logMessage + " for requestURI=" + requestURI;
        }
        String requestReceivedTime = (String) ((Axis2MessageContext) messageContext).getAxis2MessageContext()
                .getProperty(APIMgtGatewayConstants.REQUEST_RECEIVED_TIME);
        if (requestReceivedTime != null) {
            long reqIncomingTimestamp = Long.parseLong(requestReceivedTime);
            incomingReqTime = new Date(reqIncomingTimestamp);
            logMessage = logMessage + " at time=" + incomingReqTime;
        }

        String remoteIP = (String) axisMC.getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        if (remoteIP != null) {
            logMessage = logMessage + " from clientIP=" + remoteIP;
        }
        return logMessage;
    }

    private void handleAuthFailure(MessageContext messageContext, APISecurityException e) {
        messageContext.setProperty(SynapseConstants.ERROR_CODE, e.getErrorCode());
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                APISecurityConstants.getAuthenticationFailureMessage(e.getErrorCode()));
        messageContext.setProperty(SynapseConstants.ERROR_EXCEPTION, e);

        Mediator sequence = messageContext.getSequence(APISecurityConstants.API_AUTH_FAILURE_HANDLER);
        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }
        // By default we send a 401 response back
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            //In case of an error it is logged and the process is continued because we're setting a fault message in the payload.
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status;
        if (e.getErrorCode() == APISecurityConstants.API_AUTH_GENERAL_ERROR) {
            status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
        } else if (e.getErrorCode() == APISecurityConstants.API_AUTH_INCORRECT_API_RESOURCE ||
                e.getErrorCode() == APISecurityConstants.API_AUTH_FORBIDDEN ||
                e.getErrorCode() == APISecurityConstants.INVALID_SCOPE) {
            status = HttpStatus.SC_FORBIDDEN;
        } else {
            status = HttpStatus.SC_UNAUTHORIZED;
            Map<String, String> headers =
                    (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
            if (headers != null) {
                headers.put(HttpHeaders.WWW_AUTHENTICATE, getAuthenticator().getChallengeString() +
                        ", error=\"invalid token\"" +
                        ", error_description=\"The access token expired\"");
                axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
            }
        }

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            setFaultPayload(messageContext, e);
        } else {
            setSOAPFault(messageContext, e);
        }
        sendFault(messageContext, status);
    }

}
