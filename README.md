**IAM-Guardian: Lightweight IAM Policy Linter**

A simple static analyzer (linter) for validating IAM configuration files.

**The Problem:** 
Often, when provisioning infrastructure (such as AWS or Kubernetes), engineers use the `*` wildcard in the `Action` or `Resource` fields to save time. This violates the Principle of Least Privilege (PoLP) and can lead to severe security incidents in the event of a service compromise.

**The Solution:** 
This script is designed to be integrated directly into CI/CD pipelines. It parses YAML manifests before they are deployed to production and forcefully aborts the build if dangerous configuration patterns are detected.
