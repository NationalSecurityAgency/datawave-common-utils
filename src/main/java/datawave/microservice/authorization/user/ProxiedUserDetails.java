package datawave.microservice.authorization.user;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import datawave.security.authorization.DatawaveUser;
import datawave.security.authorization.DatawaveUser.UserType;
import datawave.security.authorization.ProxiedDatawaveUser;
import datawave.security.authorization.SubjectIssuerDNPair;
import datawave.security.util.ProxiedEntityUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A {@link UserDetails} that represents a set of proxied users. For example, this proxied user could represent a GUI server acting on behalf of a user. The GUI
 * server user represents the entity that made the call to us, but the user is the actual end user.
 */
@XmlRootElement
public class ProxiedUserDetails implements ProxiedDatawaveUser, UserDetails {
    private String username;
    private List<DatawaveUser> proxiedUsers = new ArrayList<>();
    private List<SimpleGrantedAuthority> roles;
    private long creationTime;
    
    @JsonCreator
    public ProxiedUserDetails(@JsonProperty("proxiedUsers") Collection<? extends DatawaveUser> proxiedUsers, @JsonProperty("creationTime") long creationTime) {
        this.proxiedUsers.addAll(proxiedUsers);
        this.username = ProxiedUserDetails.orderProxiedUsers(this.proxiedUsers).stream().map(DatawaveUser::getName).collect(Collectors.joining(" -> "));
        this.roles = getPrimaryUser().getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        this.creationTime = creationTime;
    }
    
    @Override
    public Collection<? extends DatawaveUser> getProxiedUsers() {
        return Collections.unmodifiableCollection(proxiedUsers);
    }
    
    @Override
    public List<String> getProxyServers() {
        // @formatter:off
        List<String> proxyServers = orderProxiedUsers(this.proxiedUsers).stream()
                .filter(u -> u.getUserType() == UserType.SERVER)
                .filter(u -> !u.equals(this.getPrimaryUser()))
                .map(DatawaveUser::getDn)
                .map(SubjectIssuerDNPair::subjectDN)
                .collect(Collectors.toList());
        // @formatter:on
        return proxyServers.isEmpty() ? null : proxyServers;
    }
    
    @Override
    public String getShortName() {
        return ProxiedEntityUtils.getShortName(getPrimaryUser().getName());
    }
    
    /**
     * Gets the {@link DatawaveUser} that represents the primary user in this ProxiedUserDetails. If there is only one DatawaveUser, then it is the primaryUser.
     * If there is more than one DatawaveUser, then the first (and presumably only) DatawaveUser whose {@link DatawaveUser#getUserType()} is
     * {@link UserType#USER} is the primary user. If no such DatawaveUser is present, then the first principal in the list is returned as the primary user. This
     * will be the first entity in the X-ProxiedEntitiesChain which should be the server that originated the request.
     *
     * @return The {@link DatawaveUser} that represents the primary user in the list of proxied users
     */
    @Override
    @JsonIgnore
    public DatawaveUser getPrimaryUser() {
        return ProxiedUserDetails.findPrimaryUser(this.proxiedUsers);
    }
    
    static protected DatawaveUser findPrimaryUser(List<DatawaveUser> datawaveUsers) {
        if (datawaveUsers.isEmpty()) {
            return null;
        } else {
            return datawaveUsers.get(findPrimaryUserPosition(datawaveUsers));
        }
    }
    
    static protected int findPrimaryUserPosition(List<DatawaveUser> datawaveUsers) {
        if (datawaveUsers.isEmpty()) {
            return -1;
        } else {
            for (int x = 0; x < datawaveUsers.size(); x++) {
                if (datawaveUsers.get(x).getUserType().equals(UserType.USER)) {
                    return x;
                }
            }
            return 0;
        }
    }
    
    /*
     * The purpose here is to return a List of DatawaveUsers where the original caller is first followed by any entities in X-ProxiedEntitiesChain in the order
     * that they were traversed and ending with the entity that made the final call. The List that is passed is not modified. This method makes the following
     * assumptions about the List that is passed to ths method: 1) The last element is the one that made the final call 2) Additional elements (if any) are from
     * X-ProxiedEntitiesChain in chronological order of the calls
     */
    static protected List<DatawaveUser> orderProxiedUsers(List<DatawaveUser> datawaveUsers) {
        List<DatawaveUser> users = new ArrayList<>();
        int position = ProxiedUserDetails.findPrimaryUserPosition(datawaveUsers);
        if (position >= 0) {
            users.add(datawaveUsers.get(position));
            if (datawaveUsers.size() > 1) {
                datawaveUsers.stream().limit(position).forEach(u -> users.add(u));
                datawaveUsers.stream().skip(position + 1).forEach(u -> users.add(u));
            }
        }
        return users;
    }
    
    @Override
    public Collection<? extends Collection<String>> getAuthorizations() {
        // @formatter:off
        return Collections.unmodifiableCollection(
                ProxiedUserDetails.orderProxiedUsers(this.proxiedUsers).stream()
                        .map(DatawaveUser::getAuths)
                        .collect(Collectors.toList()));
        // @formatter:on
    }
    
    @Override
    public String[] getDNs() {
        // @formatter:off
        return ProxiedUserDetails.orderProxiedUsers(this.proxiedUsers).stream()
                .map(DatawaveUser::getDn)
                .map(SubjectIssuerDNPair::subjectDN)
                .toArray(String[]::new);
        // @formatter:on
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        
        ProxiedUserDetails that = (ProxiedUserDetails) o;
        
        if (!username.equals(that.username))
            return false;
        return proxiedUsers.equals(that.proxiedUsers);
    }
    
    @Override
    public int hashCode() {
        int result = username.hashCode();
        result = 31 * result + proxiedUsers.hashCode();
        return result;
    }
    
    @Override
    public String toString() {
        // @formatter:off
        return "ProxiedUserDetails{" +
                "username='" + username + '\'' +
                ", proxiedUsers=" + ProxiedUserDetails.orderProxiedUsers(proxiedUsers) +
                '}';
        // @formatter:on
    }
    
    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }
    
    @Override
    @JsonIgnore
    public String getPassword() {
        return "";
    }
    
    @Override
    @JsonIgnore
    public String getUsername() {
        return username;
    }
    
    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }
    
    public long getCreationTime() {
        return creationTime;
    }
}
