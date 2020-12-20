package com.example.saml.filter;


import ch.qos.logback.classic.Logger;
import com.example.saml.constant.SPConstants;
import com.example.saml.utils.OpenSAMLUtils;
import com.example.saml.utils.SPCredentials;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

@WebFilter(filterName = "loginFilter", urlPatterns = "/*")
public class SpFilter implements Filter {
    private static Logger logger = (Logger) LoggerFactory.getLogger(SpFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        logger.info("过滤器初始化");
        JavaCryptoValidationInitializer javaCryptoValidationInitializer =
                new JavaCryptoValidationInitializer();
        try {
            //这个方法应该在OpenSAML初始化之前被调用，
            //来确保当前的JCE环境可以符合要求：AES/CBC/ISO10126Padding
            // 对于XML的加密，JCE需要支持ACE（128/256），并使用ISO10126Padding（填充位）
            javaCryptoValidationInitializer.init();
        } catch (InitializationException e) {
            e.printStackTrace();
        }

        //打印当前已经被安装的所有JCE的provider
        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }

        try {
            logger.info("Initializing");
            //正式初始化ＳＡＭＬ服务
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Initialization failed");
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        logger.info("请求进入过滤器");
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;

        // 如果用户已经通过身份鉴别，则session中会有AUTHENTICATED_SESSION_ATTRIBUTE，
        // 此时用户是已经被认证的，过滤器应该不对该操作做任何处理；
        if (httpServletRequest.getSession()
                .getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            filterChain.doFilter(servletRequest, servletResponse);
        } else { // 反之，则意味着需要开启鉴别流程：保留当前的目标URL，然后重定向到IDP。
            setGotoURLOnSession(httpServletRequest);
            redirectUserForAuthentication(httpServletResponse);
        }
    }

    /**
     * 将本来要访问的目标路径保存到Session
     */
    private void setGotoURLOnSession(HttpServletRequest request) {
        request.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE, request.getRequestURL().toString());
    }

    /**
     * 构建AuthnRequest对象
     * {@link SpFilter#buildAuthnRequest()}
     */
    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletResponse, authnRequest);

    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {

        MessageContext context = new MessageContext();
        context.setMessage(authnRequest);
        //关于传输对端实体的信息，对于IDP就是SP，对于SP就是IDP；
        SAMLPeerEntityContext peerEntityContext =
                context.getSubcontext(SAMLPeerEntityContext.class, true);
        //端点信息；
        SAMLEndpointContext endpointContext =
                peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(getIPDEndpoint());
        //数据签名环境上线文
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        //获得证书，其中包含公钥
        signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
        //ALGO_ID_SIGNATURE_RSA_SHA256
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        context.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);

        // OpenSAML提供了HTTPRedirectDefalteEncoder
        // 它将帮助我们来对于AuthnRequest进行序列化和签名
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        logger.info("Redirecting to IDP");
        try {
            //*encode*方法将会压缩消息，生成签名，添加结果到URL并从定向用户到Idp.
            //先使用RFC1951作为默认方法压缩数据，在对压缩后的数据信息Base64编码
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(getIPDSSODestination());
        return endpoint;
    }

    private AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        //请求时间：该对象创建的时间，以判断其时效性
        authnRequest.setIssueInstant(new DateTime());
        //目标URL：目标地址，IDP地址
        authnRequest.setDestination(getIPDSSODestination());
        //传输SAML断言所需要的绑定：也就是用何种协议使用Artifact来取回真正的认证信息，
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        //SP地址： 也就是SAML断言返回的地址
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
        //请求的ID：为当前请求设置ID，一般为随机数
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        //Issuer： 发行人信息，也就是SP的ID，一般是SP的URL
        authnRequest.setIssuer(buildIssuer());
        //NameID：IDP对于用户身份的标识；NameID policy是SP关于NameID是如何创建的说明
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        // 请求认证上下文（requested Authentication Context）:
        // SP对于认证的要求，包含SP希望IDP如何验证用户，也就是IDP要依据什么来验证用户身份。
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

        return authnRequest;
    }

    private String getIPDSSODestination() {
        return SPConstants.SSO_SERVICE;
    }

    private String getAssertionConsumerEndpoint() {
        return SPConstants.ASSERTION_CONSUMER_SERVICE;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());
        return issuer;
    }

    private String getSPIssuerValue() {
        return SPConstants.SP_ENTITY_ID;
    }

    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);
        return nameIDPolicy;
    }

    private RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);
        return requestedAuthnContext;
    }

    @Override
    public void destroy() {

    }
}
