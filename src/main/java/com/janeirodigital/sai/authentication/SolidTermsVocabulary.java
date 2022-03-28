package com.janeirodigital.sai.authentication;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;

/**
 * Properties and classes of the
 * <a href="http://www.w3.org/ns/solid/terms#">Solid Terms vocabulary</a>
 */
public class SolidTermsVocabulary {

    private SolidTermsVocabulary() { }

    private static Model model = ModelFactory.createDefaultModel();

    // Namespace
    private static final String NS = "http://www.w3.org/ns/solid/terms#";
    public static final Resource NAMESPACE = model.createResource(NS);

    // Solid Terms
    public static final Property SOLID_OIDC_ISSUER = model.createProperty(NS + "oidcIssuer");

}
