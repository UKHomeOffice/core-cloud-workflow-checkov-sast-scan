from __future__ import annotations

from typing import Any

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class S3PCIPrivateACL(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure PCI Scope buckets has private ACL (enable public ACL for non-pci buckets)"
        id = "CKV_CCL_CUSTOM_001"
        supported_resources = ("aws_s3_bucket",)
        categories = (CheckCategories.BACKUP_AND_RECOVERY,)
        guideline = "Follow the link to get more info https://docs.prismacloud.io/en/enterprise-edition/policy-reference"
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources, guideline=guideline)

    def scan_resource_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        """
            Looks for ACL configuration at aws_s3_bucket and Tag values:
            https://www.terraform.io/docs/providers/aws/r/s3_bucket.html
        :param conf: aws_s3_bucket configuration
        :return: <CheckResult>
        """
        tags = conf.get("tags")

        if tags and isinstance(tags, list):
            tags = tags[0]

        # ADDED: Check if tags is a dictionary before trying to access it.
        # This handles cases where tags are unresolved variables during HCL scanning.
        if isinstance(tags, dict):
            if tags.get("Scope") == "PCI":
                # Ensure the 'acl' key exists before accessing it
                if 'acl' in conf:
                    acl_block = conf['acl']
                    if acl_block in [["public-read"], ["public-read-write"], ["website"]]:
                        return CheckResult.FAILED
                # If the tag is PCI but there is no ACL defined, it is implicitly private, so it passes.
                return CheckResult.PASSED

        # If tags are not a dictionary (e.g., an unresolved variable string) or the Scope is not PCI,
        # the rule does not apply, so we pass.
        return CheckResult.PASSED


check = S3PCIPrivateACL()
