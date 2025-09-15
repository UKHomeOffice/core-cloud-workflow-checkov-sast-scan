# core-cloud-workflow-checkov-sast-scan

## Overview
This repository contains reusable Github Actions workflow files.

# Checkov

## Overview
This is a reusable workflow for SAST scanning source code and artifacts. This is a mandatory requirement for all Core Cloud repositories. If you require implementation assistance or have any additional questions, please reach out to Team Sauron.

There are 2 Checkov reusable workflow files that your workflow can use. NOTE: These are for informational purposes only.

1. [checkov-scan-base.yaml](https://github.com/UKHomeOffice/core-cloud-workflow-checkov-sast-scan/.github/workflows/checkov-scan-base.yaml) - For scanning [compatible](https://spacelift.io/blog/what-is-checkov#what-is-checkov) source code at rest.
2. [checkov-scan-tfplan.yaml](https://github.com/UKHomeOffice/core-cloud-workflow-checkov-sast-scan/.github/workflows/checkov-scan-tfplan.yaml) - Only to be used for scanning Terraform plan files.
## Implementation for source code 
The simplest config to use is:

     name: Checkov SAST Scan
     
     on:
       workflow_call:

     permissions:
       contents: read
       id-token: write
       actions: read
       security-events: write

     jobs:
       checkov-scan:
         uses: UKHomeOffice/core-cloud-workflow-checkov-sast-scan/.github/workflows/checkov-scan-base.yaml@1.3.0

## Inplementation for Terraform Plan files

Add the above config into the following directory in your repository `.github/workflow/checkov-scan-tfplan.yaml`, or build into your own workflow logic if more complex. For scanning Terraform Plan files as well, please use:

     name: "Checkov SAST Scan for Terraform .tfplan files as well as source code"
     
     on:
       workflow_dispatch:
       push:
         branches:
           - '*'
         paths:
           - ./**
       pull_request:
         branches:
           - main
         types:
           - opened
           - synchronize
         paths:
           - ./**
     
     permissions:
       contents: read
       id-token: write
       actions: read
       security-events: write
     
     jobs:
       sast-checkov-scan-plan:
         uses: UKHomeOffice/core-cloud-workflow-checkov-sast-scan/.github/workflows/checkov-scan-tfplan.yaml@1.3.0
         with:
           # Optional inputs depending on code structure
           path: 'e.g. terraform/environment/sandbox-ops-tooling'
           env_name: 'e.g. sandbox-ops-tooling'
           plan_role: '<role with permissions for generating a plan>'
         # Github secret containing the AWS Account ID.
         secrets:
           account_id: ${{ e.g secrets.corecloud_sandbox_ops_tooling_account_id }}

## Custom Policies

Core Cloud centrally manages custom policies within this repo. These can be found at [central-checkov-policies](https://github.com/UKHomeOffice/core-cloud-workflow-checkov-sast-scan/central-checkov-policies) and are run against all repos. If you wish to add additional custom policies after developing and testing these locally, please raise a PR and contact Team Sauron who will carry out further testing before merging for general use. Checkov supports policies written in both YAML and Python. Example policies are provided for both formats with IDs CKV_CCL_CUSTOM_001 and CKV_CCL_CUSTOM_002.
