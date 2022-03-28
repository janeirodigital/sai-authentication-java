package com.janeirodigital.sai.authentication;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * Properties and classes of the
 * <a href="https://www.w3.org/ns/solid/oidc#">Solid OIDC vocabulary</a>
 */
public class SolidOidcVocabulary {

    private SolidOidcVocabulary() { }

    private static Model model = ModelFactory.createDefaultModel();

    // Namespace
    private static final String NS = "http://www.w3.org/ns/solid/oidc#";
    public static final Resource NAMESPACE = model.createResource(NS);

    // Solid-OIDC Properties
    public static final Property SOLID_OIDC_APPLICATION_TYPE = model.createProperty(NS + "application_type");
    public static final Property SOLID_OIDC_CLIENT_ID = model.createProperty(NS + "client_id");
    public static final Property SOLID_OIDC_CLIENT_NAME = model.createProperty(NS + "client_name");
    public static final Property SOLID_OIDC_CLIENT_URI = model.createProperty(NS + "client_uri");
    public static final Property SOLID_OIDC_CONTACTS = model.createProperty(NS + "contacts");
    public static final Property SOLID_OIDC_DEFAULT_MAX_AGE = model.createProperty(NS + "default_max_age");
    public static final Property SOLID_OIDC_GRANT_TYPES = model.createProperty(NS + "grant_types");
    public static final Property SOLID_OIDC_LOGO_URI = model.createProperty(NS + "logo_uri");
    public static final Property SOLID_OIDC_POLICY_URI = model.createProperty(NS + "policy_uri");
    public static final Property SOLID_OIDC_REDIRECT_URIS = model.createProperty(NS + "redirect_uris");
    public static final Property SOLID_OIDC_REQUIRE_AUTH_TIME = model.createProperty(NS + "require_auth_time");
    public static final Property SOLID_OIDC_RESPONSE_TYPES = model.createProperty(NS + "response_types");
    public static final Property SOLID_OIDC_SCOPE = model.createProperty(NS + "scope");
    public static final Property SOLID_OIDC_TOKEN_ENDPOINT_AUTH = model.createProperty(NS + "token_endpoint_auth_method");
    public static final Property SOLID_OIDC_TOS_URI = model.createProperty(NS + "tos_uri");
}
