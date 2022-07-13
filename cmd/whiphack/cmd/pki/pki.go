// Copyright (c) technicianted. All rights reserved.
// Licensed under the MIT License.
package pki

import (
	"crypto/x509/pkix"
	"time"

	"github.com/technicianted/whip/cmd/whiphack/cmd"

	"github.com/spf13/cobra"
)

var PKICMD = &cobra.Command{
	Use:   "pki",
	Short: "collection of hacking tools for whip",
}

var (
	CACertPath       string
	CAKeyPath        string
	ValidityDuration time.Duration
	Subject          = pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Github"},
		OrganizationalUnit: []string{"Technicianted"},
	}
)

func init() {
	PKICMD.PersistentFlags().StringVar(&CACertPath, "ca-cert-path", "ca-cert.pem", "path to ca certificate pem file")
	PKICMD.PersistentFlags().StringVar(&CAKeyPath, "ca-key-path", "ca-key.pem", "path to ca key pem file")
	PKICMD.PersistentFlags().DurationVar(&ValidityDuration, "validity-duration", 30*24*time.Hour, "validity duration of the certificate")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.Country, "country", Subject.Country, "certificate subject country")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.Organization, "organization", Subject.Organization, "certificate subject organization")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.OrganizationalUnit, "organization-unit", Subject.OrganizationalUnit, "certificate subject organization unit")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.Locality, "locality", Subject.Locality, "certificate subject locality")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.Province, "province", Subject.Province, "certificate subject provence")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.StreetAddress, "street", Subject.StreetAddress, "certificate subject street address")
	PKICMD.PersistentFlags().StringSliceVar(&Subject.PostalCode, "postal-code", Subject.PostalCode, "certificate subject postal code")
	PKICMD.PersistentFlags().StringVar(&Subject.SerialNumber, "serial", Subject.SerialNumber, "certificate serial number")
	PKICMD.PersistentFlags().StringVar(&Subject.CommonName, "common-name", Subject.CommonName, "certificate common name")

	cmd.RootCMD.AddCommand(PKICMD)
}
