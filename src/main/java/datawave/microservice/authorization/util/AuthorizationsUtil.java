package datawave.microservice.authorization.util;

import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import datawave.accumulo.util.security.UserAuthFunctions;
import datawave.microservice.authorization.user.DatawaveUserDetails;
import datawave.security.authorization.DatawaveUser;
import datawave.security.util.AuthorizationsMinimizer;
import org.apache.accumulo.core.security.Authorizations;
import org.apache.commons.lang.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class AuthorizationsUtil {
    
    public static Authorizations union(Iterable<byte[]> authorizations1, Iterable<byte[]> authorizations2) {
        LinkedList<byte[]> aggregatedAuthorizations = Lists.newLinkedList();
        addTo(aggregatedAuthorizations, authorizations1);
        addTo(aggregatedAuthorizations, authorizations2);
        return new Authorizations(aggregatedAuthorizations);
    }
    
    private static void addTo(LinkedList<byte[]> aggregatedAuthorizations, Iterable<byte[]> authsToAdd) {
        for (byte[] auth : authsToAdd) {
            aggregatedAuthorizations.add(auth);
        }
    }
    
    public static Set<Authorizations> mergeAuthorizations(String requestedAuths, Collection<? extends Collection<String>> userAuths) {
        HashSet<String> requested = null;
        if (!StringUtils.isEmpty(requestedAuths)) {
            requested = new HashSet<>(splitAuths(requestedAuths));
        }
        
        if (null == userAuths)
            return Collections.singleton(new Authorizations());
        
        HashSet<Authorizations> mergedAuths = new HashSet<>();
        HashSet<String> missingAuths = (requested == null) ? new HashSet<>() : new HashSet<>(requested);
        for (Collection<String> auths : userAuths) {
            if (null != requested) {
                missingAuths.removeAll(auths);
                auths = new HashSet<>(auths);
                auths.retainAll(requested);
            }
            
            mergedAuths.add(new Authorizations(auths.toArray(new String[auths.size()])));
        }
        
        if (!missingAuths.isEmpty()) {
            throw new IllegalArgumentException("User requested authorizations that they don't have. Missing: " + missingAuths + ", Requested: " + requested
                            + ", User: " + userAuths);
        }
        return mergedAuths;
    }
    
    /**
     * Retrieves a set of "downgraded" authorizations. This retrieves all authorizations from {@code principal} and intersects the user auths (the
     * authorizations retrieved from {@code principal} for {@link DatawaveUserDetails#getPrimaryUser()}) with {@code requestedAuths}. All other entity auths
     * retrieved from {@code principal}, if any, are included in the result set as is. If {@code requestedAuths} contains any authorizations that are not in the
     * user auths list, then an {@link IllegalArgumentException} is thrown.
     *
     * @param requestedAuths
     *            The auths to use for the user's auths. If this list contains any that are not owned by the user, an {@link IllegalArgumentException} is
     *            thrown.
     * @param currentUser
     *            The principal from which to retrieve entity authorizations.
     * @return A set of {@link Authorizations}, one per entity represented in {@code principal}. The user's auths are replaced by {@code requestedAuths} so long
     *         as the user actually had all of the auths. If {@code requestedAuths} is {@code null}, then the user's auths are returned as-is.
     */
    public static LinkedHashSet<Authorizations> getDowngradedAuthorizations(String requestedAuths, DatawaveUserDetails currentUser) {
        
        final DatawaveUser primaryUser = currentUser.getPrimaryUser();
        UserAuthFunctions uaf = UserAuthFunctions.getInstance();
        return uaf.mergeAuthorizations(uaf.getRequestedAuthorizations(requestedAuths, primaryUser), currentUser.getProxiedUsers(), u -> u != primaryUser);
    }
    
    /**
     * Similar functionality to the above getDowngradedAuths, but returns in a Stringas opposed to a Set, and only returns the user's auths and not those for
     * any chained entity. This makes it easier to swap out queryParameters to use for createQueryAndNext(). Uses buildAuthorizationString to find the
     * authorizations the user has and compares those to the authorizations requested. Verifies that the user has access to the authorizations, and will return
     * the downgraded authorities if they are valid. If the request authorities they don't have, or request not authorizations, an exception is thrown.
     *
     * @param currentUser
     *            the principal representing the user to verify that {@code requested} are all valid authorizations
     * @param requested
     *            the requested downgrade authorizations
     * @return requested, unless the user represented by {@code principal} does not have one or more of the auths in {@code requested}
     */
    public static String downgradeUserAuths(DatawaveUserDetails currentUser, String requested) {
        if (requested == null || requested.trim().isEmpty()) {
            throw new IllegalArgumentException("Requested authorizations must not be empty");
        }
        
        List<String> requestedList = AuthorizationsUtil.splitAuths(requested);
        // Find all authorizations the user has access to
        String userAuths = AuthorizationsUtil.buildUserAuthorizationString(currentUser);
        List<String> userList = AuthorizationsUtil.splitAuths(userAuths);
        List<String> missingAuths = new ArrayList<>();
        List<String> finalAuthsList = new ArrayList<>();
        
        for (String temp : requestedList) {
            // user requested auth they don't have
            if (!userList.contains(temp)) {
                missingAuths.add(temp);
            } else { // user requested auth they do have
                finalAuthsList.add(temp);
            }
        }
        // All auths requested are auths the user has, return downgraded string for auths
        if (missingAuths.isEmpty()) {
            return AuthorizationsUtil.buildAuthorizationString(Collections.singletonList(finalAuthsList));
        } else {// missing auths.size() > 0; user requested auths they don't have
            throw new IllegalArgumentException("User requested authorizations that they don't have. Missing: " + missingAuths + ", Requested: " + requested
                            + ", User: " + userAuths);
        }
    }
    
    public static List<String> splitAuths(String requestedAuths) {
        return Arrays.asList(Iterables.toArray(Splitter.on(',').omitEmptyStrings().trimResults().split(requestedAuths), String.class));
    }
    
    public static Set<Authorizations> buildAuthorizations(Collection<? extends Collection<String>> userAuths) {
        if (null == userAuths) {
            return Collections.singleton(new Authorizations());
        }
        
        HashSet<Authorizations> auths = Sets.newHashSet();
        for (Collection<String> userAuth : userAuths) {
            auths.add(new Authorizations(userAuth.toArray(new String[userAuth.size()])));
        }
        
        return auths;
    }
    
    public static String buildAuthorizationString(Collection<? extends Collection<String>> userAuths) {
        if (null == userAuths) {
            return "";
        }
        
        HashSet<byte[]> b = new HashSet<>();
        for (Collection<String> userAuth : userAuths) {
            for (String string : userAuth) {
                b.add(string.getBytes(StandardCharsets.UTF_8));
            }
        }
        
        return new Authorizations(b).toString();
    }
    
    public static String buildUserAuthorizationString(DatawaveUserDetails currentUser) {
        String auths = "";
        if (currentUser != null) {
            auths = new Authorizations(currentUser.getPrimaryUser().getAuths().toArray(new String[0])).toString();
        }
        return auths;
    }
    
    public static Collection<Authorizations> minimize(Collection<Authorizations> authorizations) {
        return AuthorizationsMinimizer.minimize(authorizations);
    }
    
    public static Collection<? extends Collection<String>> prepareAuthsForMerge(Authorizations authorizations) {
        return Collections.singleton(new HashSet<>(Arrays.asList(authorizations.toString().split(","))));
    }
}
