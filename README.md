# NCSC-MDM

## DeviceConfiguration_Import.ps1
This script imports the current NCSC MDM Device Configuration guidance.

More details on the guidance can be found here https://www.ncsc.gov.uk/collection/mobile-device-guidance/platform-guides/windows-10 along with the source of the JSON configuration files.

The script will prompt if you wish to assign the Device Configuration Policies to a specific group.  If you select Yes, a second prompt will ask for a valid Azure AD group.  The script will then add all policies and assign them to the same group.

If you select No to assigning a group, then the script will add all policies without group membership.

The script will check if policies with the same name exists and will not add the policies if they do.  This is to stop duplication.

## PolicySets_Import.ps1

This script creates a PolicySet and assigns the NCSC Device Configuration policies to the new PolicySet.


