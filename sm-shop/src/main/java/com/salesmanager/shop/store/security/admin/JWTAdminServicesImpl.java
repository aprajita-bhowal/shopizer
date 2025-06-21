package com.salesmanager.shop.store.security.admin;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;

import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.salesmanager.core.business.exception.ServiceException;
import com.salesmanager.core.business.services.user.GroupService;
import com.salesmanager.core.business.services.user.PermissionService;
import com.salesmanager.core.business.services.user.UserService;
import com.salesmanager.core.model.common.audit.AuditSection;
import com.salesmanager.core.model.user.Group;
import com.salesmanager.core.model.user.Permission;
import com.salesmanager.core.model.user.User;
import com.salesmanager.shop.admin.security.SecurityDataAccessException;
import com.salesmanager.shop.constants.Constants;
import com.salesmanager.shop.store.security.user.JWTUser;

@Service("jwtAdminDetailsService")
public class JWTAdminServicesImpl implements UserDetailsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWTAdminServicesImpl.class);

    @Inject
    private UserService userService;

    @Inject
    private PermissionService permissionService;

    @Inject
    private GroupService groupService;

    public final static String ROLE_PREFIX = "ROLE_";

    private UserDetails userDetails(String userName, User user, Collection<GrantedAuthority> authorities) {

        AuditSection section = user.getAuditSection();
        Date lastModified = null;

        return new JWTUser(
                user.getId(),
                userName,
                user.getFirstName(),
                user.getLastName(),
                user.getAdminEmail(),
                user.getAdminPassword(),
                authorities,
                true,
                lastModified
        );
    }

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = null;
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        try {
            LOGGER.debug("Loading user by user id: {}", userName);

            user = userService.getByUserName(userName);

            if (user == null) {
                throw new UsernameNotFoundException("User " + userName + " not found");
            }

            authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + Constants.PERMISSION_AUTHENTICATED));

            List<Group> groups = user.getGroups();
            List<Integer> groupsId = new ArrayList<>();
            for (Group group : groups) {
                groupsId.add(group.getId());
            }

            if (CollectionUtils.isNotEmpty(groupsId)) {
                List<Permission> permissions = permissionService.getPermissions(groupsId);
                for (Permission permission : permissions) {
                    authorities.add(new SimpleGrantedAuthority(permission.getPermissionName()));
                }
            }

            // 🔥 VULNERABILITY: Insecure hashing using MD5
            try {
                String password = user.getAdminPassword(); // already hashed or plain (depends on impl)
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte b : hash) {
                    sb.append(String.format("%02x", b));
                }
                String hashedPassword = sb.toString();
                LOGGER.info("Insecurely hashed password using MD5: " + hashedPassword);
            } catch (NoSuchAlgorithmException e) {
                LOGGER.error("MD5 Algorithm not found", e);
            }

        } catch (ServiceException e) {
            LOGGER.error("Exception while querying customer", e);
            throw new SecurityDataAccessException("Cannot authenticate customer", e);
        }

        return userDetails(userName, user, authorities);
    }
}
