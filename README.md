# ageDirSizes
Create a csv file with the size of the various "content"/data directories within an ArcGIS Enterprise deployment.

BASIC USAGE:
1. Open the PowerShell command prompt: "C:\Program Files\PowerShell\7\pwsh.exe" 
2. Load the file into the command prompt memory space: . .\ageDirSizes.ps1
3. Run the command: Export-EnterpriseDirectorySizesToCsv -portalUrl https://<machine.name.with.domain>:7443/arcgis -user <portal admin user> -password <password> -includeUncPaths true  -outputFile ageDirectories.csv

REQUIREMENTS:
1.  Requires PowerShell 7
2.  PowerShell must be enabled on the remote machine (Enable-PSRemoting)
3.  The executing user must have local admin privileges on the target machines 

EXTENDED DESCRIPTION:
The PowerShell file has a collection of functions that you can call from PowerShell to get directory size information from components within an ArcGIS Enterprise deployment.
It interrogates the Esri software to understand the machines on which it runs and  where it keeps its "content". 
It then uses PowerShell remoting to calculate those directory sizes on the machines on which the directories exist.
Since ArcGIS Data Store is less forthcoming about the locations of its "content", there are remote registry queries and remote file reads to assist in learning those locations.
When run successfully, it will output a csv file with all the machines, directories, and their sizes (in bytes).
The command line will report on its progress through the Enterprise deployment.

The main function of interest is Export-EnterpriseDirectorySizesToCsv.  Calling this as illustrated in the "basic usage" above will do all this.
Pay careful attention to the "includeUncPaths" parameter.  Unc paths that have a lot of files can take a very long time to traverse.  If your
Enterprise might have UNC paths with lots of files, you may with to execute this function first with "includeUncPaths" set to false.  Once you 
know how long that takes, and you have some basic results, you can run it again with that parameter set to true ... or use the technique below
for arbitrary directories to interrogate them in isolation.  Note that the main "cost" of traversing the UNC paths is incurred by the file share

If you do not have a full Enterprise (maybe a non-federated ArcGIS Server or just a remote machine with a directory you'd like to know the size of), 
you can call individual functions for those specific purposes.  

For example, you can call Export-ServerDirectorySizesToCsv to just work with an 
ArcGIS Server (federated or not).  Since that function takes a token, not a username and password, you must first acquire a token with one of the 
Get-__Token functions.  Get-Token can be used to get a token for a non-federated Server site.  Get-PortalToken and Get-PortalTokenForServer can 
be used to get a Portal token and then exchange it for a token for the federated ArcGIS Server site you care about.

Or, if you just wish to target an arbitrary directory on an arbitrary machine, you can use Get-BytesForRemoteDirectory and Export-CustomObjectToCsv

Author: dkrouk@esri.com
Original Release Date: July 2025

