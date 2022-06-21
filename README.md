# OGMA and BORVO: Automated Container Security Visualisation and Remediation

OGMA is a visualisation tool for improved analysis and assessment of container security issues across multiple scanning tools.

BORVO is a proof of concept tool that automatically updates container images where fixed binaries are available without impacting usability.

## Installation

To install OGMA and BORVO, git clone the repository

```
git clone https://github.com/amills157/tuatha_de.git
```

## Pre-requisites
To run OGMA and BORVO install the Python dependencies.

```
pip3 install -r ./requirements.txt
```

After installation is complete, initialise the CVEDB local database. NOTE: `cvedb` will be in the path `~/.local/bin` so ensure that this is in your `$PATH`.

```
cvedb -u
```
## Scanners

OGMA supports analysing the output from a number of scanning tools. Supported scanners are:

- Dagda
- Docker Scan
- Clair
- Grype
- Trivy
- Sysdig

The scanner output must be of the type specified in the scanner section. The output file should be placed in the relevant subdirectory under the base reporting directory (Default: `container_scans`)

All scanner output files should be named in a safe file name format with colons `:`, hyphens `-` and dots `.` replaced with underscores `_`.

Example:

`redis:7.0.0` should be named `redis_7_0_0`

### Dagda

Dagda is a tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities.

Dagda installation and usage instructions can be found in the tool's repository - https://github.com/eliasgranderubio/dagda

Dagda output should be in JSON format.

#### Example

Submit image for check to Dagda
```
#!/bin/sh
for i in $(cat docker_images.txt); do

  python3 dagda.py check --docker_image $i

done
```

Obtain Dagda output

```
#!/bin/sh
for i in $(cat docker_images.txt); do

  j="${i//./_}"
  k="${j//:/_}"
  l="${k////_}"

  python3 dagda.py history $i > dagda/scans/$l.json

done
```

### Docker Scan
Docker Scan runs on Snyk engine, providing users with visibility into the security posture of their local Dockerfiles and local images.

Users trigger vulnerability scans through the CLI, and use the CLI to view the scan results.

https://docs.docker.com/engine/scan/

Docker Scan output should be in JSON.

#### Example
```
#!/bin/sh
for i in $(cat docker_images.txt); do

  j="${i//./_}"
  k="${j//:/_}"
  l="${k////_}"

  docker scan --json $i > docker_scan/scans/$l.json

done
```

### Clair
Clair is an open source project which provides a tool to monitor the security of your containers through the static analysis of vulnerabilities in appc and docker containers. Clair is an API-driven analysis engine that inspects containers layer-by-layer for known security flaws.

Server - https://github.com/arminc/clair-local-scan

Scanner - https://github.com/arminc/clair-scanner

Clair output should be in JSON.

#### Example

```
#!/bin/sh
for i in $(cat docker_images.txt); do

  j="${i//./_}"
  k="${j//:/_}"
  l="${k////_}"

  clair-scanner --ip <YOUR IP> -r clair/scans/$l.json $i

done
```

Please note that for the clair scanner using 127.0.0.1 will likely result in issues / errors

### Grype

A vulnerability scanner for container images and filesystems. Easily install the binary to try it out. Works with Syft, the powerful SBOM (software bill of materials) tool for container images and filesystems.

https://github.com/anchore/grype

Grype output should be in text (.txt) format

#### Example
```
#!/bin/sh
for i in $(cat docker_images.txt); do

  j="${i//./_}"
  k="${j//:/_}"
  l="${k////_}"

  grype $i > grype/scans/$l.txt

done
```

#### Trivy
A Simple and Comprehensive Vulnerability Scanner for Containers and other Artifacts, Suitable for CI.

https://aquasecurity.github.io/trivy/

Trivy output should be in text (.json) format

#### Example

```
#!/bin/sh

for i in $(cat docker_images.txt); do

j="${i//./_}"
k="${j//:/_}"
l="${k////_}"

trivy image -f json -o trivy/$l.json $i

done
```

### Sysdig
Sysdig is a universal system visibility tool with support for containers. Sysdig hooks itself into the machine's kernel and segregates the information on a per-container basis.

Sysdig is a commercial solution that requires a paid subscription. A 30-day free trial is available.

https://sysdig.com/

Images are submitted, and the output CSV can be downloaded through the Sysdig portal.

## How to Run OGMA

NOTE: The first run will take approximately 1 hour due to needing to create the local DB required for cve-searchsploit.

### Scanner Output Location
Prior to launching OGMA, you must have the scanner output files in the `report_dir` directory (**Default:** `container_scans`)

### Usage
```
usage: ogma.py [-h] [-input INPUT] [-format FORMAT] -image IMAGE [-container CONTAINER] [-update UPDATE] [-refresh REFRESH] [-vis VIS] [-nofix NOFIX]
```

 - `report_dir` = Directory folder which contains the the reports or scan result(s) to read. If not provided this will default to the 'container_scans' folder in the same root dir
  - `format` = The scanner tool used - Accepted values are: All, Clair, Dagda, Docker_Scan, Grype,Sysdig, Trivy. Defaults to 'all'
  - `image` = The container image file report to use - This will also be the data name used when plotting and the file name for the output, e.g. 'rabbitmq_3_9_13'
  - `container` = The container / application name to use - This will be the central node name used when plotting, e.g. `rabbitmq`
  - `update` = Will use the BOROVO plugin to fix impacted binaries (where possible)
  - `refresh` = Will re-create the node and egdes from the container scan results available - By default visulisations are created from existing node and edge files (when / where they exist)
  - `vis` = Select the visualisation output. Single (node), Multi (node) or Both. This defaults to 'both' for all scanners and single for a selected format"
  - `nofix` = Select to show CVEs which have been listed as won't / no fix - defaults to 'False'

### Scan Individual Image
```
./ogmay.py -image <image> -refresh true -container <name>
```

### Scanning Multiple Images

You can scan multiple images easily using the provided `ogma_runner.sh` script. Create a text file called `image_list.txt` containing the names of the docker images to scan, then execute the provided script

```
./ogma_runner.sh
```
