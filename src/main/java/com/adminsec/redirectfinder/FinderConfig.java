package com.adminsec.redirectfinder;

import burp.api.montoya.persistence.Preferences;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

public final class FinderConfig {
    public static final Set<String> DEFAULT_PARAMETERS = normalizedSet("""
            next,url,uri,redirect,redirect_url,redirect_uri,redirecturl,redirecturi,
            return,return_url,returnurl,return_to,returnto,returl,dest,destination,
            continue,continueto,callback,callback_url,callbackurl,goto,go,target,to,
            from,back,origin,ref,referrer,referer,relaystate,post_logout_redirect_uri,
            continueaftersignin,success_url,failure_url,cancel_url,forward,forward_url,
            redir,redirect_to,return_path
            """);
    public static final Set<String> DEFAULT_SINKS = normalizedSet("""
            redirect,returnurl,callbackurl,continueaftersignin,refresh,
            window.location,document.location,top.location,parent.location,self.location,
            location.href,location.assign,location.replace,navigateto,router.push,
            router.replace,response.redirect,http-equiv=\"refresh\",http-equiv='refresh'
            """);
    public static final Set<String> DEFAULT_SOURCES = normalizedSet("""
            location.search,location.hash,document.referrer,document.url,document.baseuri,
            postmessage,event.data,window.name,localstorage,sessionstorage,cookie,document.cookie,
            route.query,urlsearchparams
            """);

    private static final String P_SCOPE = "redirectFinder.scopeOnly";
    private static final String P_MAX = "redirectFinder.maxResponseBytes";
    private static final String P_PARAMS = "redirectFinder.parameters";
    private static final String P_SINKS = "redirectFinder.sinks";
    private static final String P_SOURCES = "redirectFinder.sources";
    private static final String P_IGNORED_HOSTS = "redirectFinder.ignoredHosts";
    private static final String P_IGNORED_MARKERS = "redirectFinder.ignoredMarkers";

    private boolean scopeOnly = true;
    private int maxResponseBytes = 5 * 1024 * 1024;
    private Set<String> parameters = new LinkedHashSet<>(DEFAULT_PARAMETERS);
    private Set<String> sinks = new LinkedHashSet<>(DEFAULT_SINKS);
    private Set<String> sources = new LinkedHashSet<>(DEFAULT_SOURCES);
    private Set<String> ignoredHosts = new LinkedHashSet<>();
    private Set<String> ignoredMarkers = new LinkedHashSet<>();

    public static FinderConfig load(Preferences preferences) {
        FinderConfig config = new FinderConfig();
        Boolean scope = preferences.getBoolean(P_SCOPE);
        Integer max = preferences.getInteger(P_MAX);
        config.scopeOnly = scope == null || scope;
        config.maxResponseBytes = max == null ? config.maxResponseBytes : Math.max(64 * 1024, max);
        config.parameters = valueOrDefault(preferences.getString(P_PARAMS), DEFAULT_PARAMETERS);
        config.sinks = valueOrDefault(preferences.getString(P_SINKS), DEFAULT_SINKS);
        config.sources = valueOrDefault(preferences.getString(P_SOURCES), DEFAULT_SOURCES);
        config.ignoredHosts = normalizedSet(nullToEmpty(preferences.getString(P_IGNORED_HOSTS)));
        config.ignoredMarkers = normalizedSet(nullToEmpty(preferences.getString(P_IGNORED_MARKERS)));
        return config;
    }

    public void save(Preferences preferences) {
        preferences.setBoolean(P_SCOPE, scopeOnly);
        preferences.setInteger(P_MAX, maxResponseBytes);
        preferences.setString(P_PARAMS, serialize(parameters));
        preferences.setString(P_SINKS, serialize(sinks));
        preferences.setString(P_SOURCES, serialize(sources));
        preferences.setString(P_IGNORED_HOSTS, serialize(ignoredHosts));
        preferences.setString(P_IGNORED_MARKERS, serialize(ignoredMarkers));
    }

    private static Set<String> valueOrDefault(String value, Set<String> defaults) {
        Set<String> parsed = normalizedSet(nullToEmpty(value));
        return parsed.isEmpty() ? new LinkedHashSet<>(defaults) : parsed;
    }

    public static Set<String> normalizedSet(String value) {
        return Arrays.stream(nullToEmpty(value).split("[,\\r\\n]+"))
                .map(String::trim).filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static String serialize(Set<String> values) { return String.join("\n", values); }
    private static String nullToEmpty(String value) { return value == null ? "" : value; }

    public boolean scopeOnly() { return scopeOnly; }
    public void scopeOnly(boolean value) { scopeOnly = value; }
    public int maxResponseBytes() { return maxResponseBytes; }
    public void maxResponseBytes(int value) { maxResponseBytes = Math.max(64 * 1024, value); }
    public Set<String> parameters() { return parameters; }
    public void parameters(Set<String> value) { parameters = new LinkedHashSet<>(value); }
    public Set<String> sinks() { return sinks; }
    public void sinks(Set<String> value) { sinks = new LinkedHashSet<>(value); }
    public Set<String> sources() { return sources; }
    public void sources(Set<String> value) { sources = new LinkedHashSet<>(value); }
    public Set<String> ignoredHosts() { return ignoredHosts; }
    public Set<String> ignoredMarkers() { return ignoredMarkers; }
}
