// Package version is the connector's version. connector.json carries the
// same string; TestVersionMatchesManifest keeps them equal.
package version

// Version is reported in the connector's hello and must equal
// connector.json's "version".
const Version = "0.1.6"
