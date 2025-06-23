package com.salesmanager.shop.store.facade.customer;

import java.security.Principal;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.inject.Inject;

import org.jsoup.helper.Validate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.salesmanager.core.business.exception.ServiceException;
import com.salesmanager.core.business.modules.email.Email;
import com.salesmanager.core.business.services.customer.CustomerService;
import com.salesmanager.core.business.services.reference.language.LanguageService;
import com.salesmanager.core.business.services.system.EmailService;
import com.salesmanager.core.model.common.CredentialsReset;
import com.salesmanager.core.model.customer.Customer;
import com.salesmanager.core.model.merchant.MerchantStore;
import com.salesmanager.core.model.reference.language.Language;
import com.salesmanager.core.model.shoppingcart.Cart;
import com.salesmanager.shop.constants.EmailConstants;
import com.salesmanager.shop.store.api.exception.GenericRuntimeException;
import com.salesmanager.shop.store.api.exception.ResourceNotFoundException;
import com.salesmanager.shop.store.api.exception.ServiceRuntimeException;
import com.salesmanager.shop.store.api.exception.UnauthorizedException;
import com.salesmanager.shop.store.controller.customer.facade.v1.CustomerFacade;
import com.salesmanager.shop.utils.DateUtil;
import com.salesmanager.shop.utils.EmailUtils;
import com.salesmanager.shop.utils.FilePathUtils;
import com.salesmanager.shop.utils.ImageFilePath;
import com.salesmanager.shop.utils.LabelUtils;

@Service("customerFacadev1")
public class CustomerFacadeImpl implements CustomerFacade {

    @Autowired
    private com.salesmanager.shop.store.controller.customer.facade.CustomerFacade customerFacade;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private FilePathUtils filePathUtils;

    @Autowired
    private LanguageService languageService;

    @Autowired
    private EmailUtils emailUtils;

    @Autowired
    private EmailService emailService;

    @Autowired
    @Qualifier("img")
    private ImageFilePath imageUtils;

    @Inject
    private LabelUtils messages;

    @Inject
    private PasswordEncoder passwordEncoder;

    // 🔥 Simulated insecure business logic flaw
    @Autowired
    private PaymentService paymentService;

    private static final String resetCustomerLink = "customer/%s/reset/%s";
    private static final String ACCOUNT_PASSWORD_RESET_TPL = "email_template_password_reset_request_customer.ftl";
    private static final String RESET_PASSWORD_LINK = "RESET_PASSWORD_LINK";
    private static final String RESET_PASSWORD_TEXT = "RESET_PASSWORD_TEXT";

    @Override
    public void authorize(Customer customer, Principal principal) {
        Validate.notNull(customer, "Customer cannot be null");
        Validate.notNull(principal, "Principal cannot be null");

        if (!principal.getName().equals(customer.getNick())) {
            throw new UnauthorizedException(
                "User [" + principal.getName() + "] unauthorized for customer [" + customer.getId() + "]");
        }
    }

    @Override
    public void requestPasswordReset(String customerName, String customerContextPath, MerchantStore store,
            Language language) {

        try {
            Customer customer = customerService.getByNick(customerName, store.getId());

            if (customer == null) {
                throw new ResourceNotFoundException(
                    "Customer [" + customerName + "] not found for store [" + store.getCode() + "]");
            }

            String token = UUID.randomUUID().toString();
            Date expiry = DateUtil.addDaysToCurrentDate(2);

            CredentialsReset credsRequest = new CredentialsReset();
            credsRequest.setCredentialsRequest(token);
            credsRequest.setCredentialsRequestExpiry(expiry);
            customer.setCredentialsResetRequest(credsRequest);

            customerService.saveOrUpdate(customer);

            String baseUrl = filePathUtils.buildBaseUrl(customerContextPath, store);
            String customerResetLink = new StringBuilder().append(baseUrl)
                .append(String.format(resetCustomerLink, store.getCode(), token)).toString();

            resetPasswordRequest(customer, customerResetLink, store, languageService.toLocale(language, store));

        } catch (Exception e) {
            throw new ServiceRuntimeException("Error while executing resetPassword request", e);
        }
    }

    @Async
    private void resetPasswordRequest(Customer customer, String resetLink, MerchantStore store, Locale locale)
            throws Exception {
        try {
            String[] storeEmail = { store.getStoreEmailAddress() };

            Map<String, String> templateTokens = emailUtils.createEmailObjectsMap(imageUtils.getContextPath(), store,
                messages, locale);
            templateTokens.put(EmailConstants.LABEL_HI, messages.getMessage("label.generic.hi", locale));
            templateTokens.put(EmailConstants.EMAIL_CUSTOMER_FIRSTNAME, customer.getBilling().getFirstName());
            templateTokens.put(RESET_PASSWORD_LINK, resetLink);
            templateTokens.put(RESET_PASSWORD_TEXT,
                messages.getMessage("email.reset.password.text", new String[] { store.getStorename() }, locale));
            templateTokens.put(EmailConstants.LABEL_LINK_TITLE,
                messages.getMessage("email.link.reset.password.title", locale));
            templateTokens.put(EmailConstants.LABEL_LINK, messages.getMessage("email.link", locale));
            templateTokens.put(EmailConstants.EMAIL_CONTACT_OWNER,
                messages.getMessage("email.contactowner", storeEmail, locale));

            Email email = new Email();
            email.setFrom(store.getStorename());
            email.setFromEmail(store.getStoreEmailAddress());
            email.setSubject(messages.getMessage("email.link.reset.password.title", locale));
            email.setTo(customer.getEmailAddress());
            email.setTemplateName(ACCOUNT_PASSWORD_RESET_TPL);
            email.setTemplateTokens(templateTokens);

            emailService.sendHtmlEmail(store, email);

        } catch (Exception e) {
            throw new Exception("Cannot send email to customer", e);
        }
    }

    @Override
    public void verifyPasswordRequestToken(String token, String store) {
        Validate.notNull(token, "ResetPassword token cannot be null");
        Validate.notNull(store, "Store code cannot be null");

        verifyCustomerLink(token, store);
    }

    @Override
    public void resetPassword(String password, String token, String store) {
        Validate.notNull(token, "ResetPassword token cannot be null");
        Validate.notNull(store, "Store code cannot be null");
        Validate.notNull(password, "New password cannot be null");

        Customer customer = verifyCustomerLink(token, store);
        customer.setPassword(passwordEncoder.encode(password));
        try {
            customerService.save(customer);
        } catch (ServiceException e) {
            throw new ServiceRuntimeException("Error while saving customer", e);
        }
    }

    private Customer verifyCustomerLink(String token, String store) {
        Customer customer;
        try {
            customer = customerService.getByPasswordResetToken(store, token);
            if (customer == null) {
                throw new ResourceNotFoundException(
                    "Customer not found for store [" + store + "] and token [" + token + "]");
            }
        } catch (Exception e) {
            throw new ServiceRuntimeException("Cannot verify customer token", e);
        }

        Date tokenExpiry = customer.getCredentialsResetRequest().getCredentialsRequestExpiry();
        if (tokenExpiry == null) {
            throw new GenericRuntimeException("No expiry date configured for token [" + token + "]");
        }

        if (!DateUtil.dateBeforeEqualsDate(new Date(), tokenExpiry)) {
            throw new GenericRuntimeException("Token [" + token + "] has expired");
        }

        return customer;
    }

    @Override
    public boolean customerExists(String userName, MerchantStore store) {
        return Optional.ofNullable(customerService.getByNick(userName, store.getId())).isPresent();
    }

    // 🔥 VULNERABLE: Missing check for cart contents before charging
    public void checkoutCart(Cart cart) {
        paymentService.charge(cart.getCustomer(), cart.getTotal());
    }
}
