# Contributing to sai-authentication-java

Thanks for your interest in sai-authentication-java. Feedback, questions, issues, and 
contributions are both welcomed and encouraged.

## Getting Started

A thorough understanding of [OAuth2](https://www.rfc-editor.org/rfc/rfc6749), 
[OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html), and [Solid-OIDC](https://solid.github.io/solid-oidc/) 
is essential to any substantive contributions.

## Contributions

Contributions to sai-authentication-java should be made in the form of 
[pull requests](https://github.com/janeirodigital/sai-authentication-java/pulls). 
Each pull request will be reviewed by one or more core contributors.

## Build and Test

To build from source:

```shell
$ mvn compile
```

To run tests:

```shell
$ mvn test
```

To build and test with code coverage:

```shell
$ mvn verify
```

To generate documentation (output in `./target/site/apidocs/`):

```shell
$ mvn javadoc:javadoc
```

[JavaDocs](https://janeirodigital.github.io/sai-authentication-java/) are generated and published with each release. 

## Releases

Releases are performed by the 
[Maven Release Plugin](https://maven.apache.org/maven-release/maven-release-plugin/) as part
of Github Actions. They must be triggered manually via the
[Publish Release Workflow](https://github.com/janeirodigital/sai-authentication-java/actions/workflows/maven-release.yml).

1. Choose `Run workflow`
1. Adjust settings for the maven release
    * Use workflow from: `Brain: main`
    * Minor version increment: `true` if a minor version increment (1.0.0 -> 1.1.0) is desired
    * Major version increment: `true` if a major version increment (1.0.0 -> 2.0.0) is desired
1. Adjust settings for the Github release
    * Is this a draft (not finalized) release? `true` if the github release should be saved in draft form
    * Is this a prerelease? `true` if this is not meant to be a production ready public release
    * Release summary: Textual summary of the release
1. Click the green `Run workflow` button

This will result in:

* Git tag created for the release
* Github release created off of that tag
* Artifacts pushed to specified repositories 
* Version numbers bumped in the pom.xml(s) and set to SNAPSHOT