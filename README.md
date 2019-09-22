# CabCloningFactory
A Python-based tool for cloning cabinet file certificates

This tool will extract the certificate off of an indicated cabinet file and use the certificate to build a new cab file with a file of your choosing.

Built-in support for both Linux and Windows as it utilizes lcab and makecab.exe respectively; however, it should be noted that makecab and lcab generate cabs slightly differently and using this tool on Windows may not succeed. Therefore, it is recommended to use Linux.  

```
Usage: CabCloningFactory.py <source cab file> <file to place in archive>
```

### Example
Script running:





File comparision:








## Why go crazy over cabs?

As a form of archive, cabinet files can be used in "Zip Slip" attacks against code or tools that are vulnerable to arbitrary file writes due to archive extraction. Concerns also exist for files that are automatically executed upon extraction.

The integrity of cabinet files are often protected via the use of digital signatures and certificates; however, it is possible to bypass signature and certificate checks through cloning techniques such as this tool.

