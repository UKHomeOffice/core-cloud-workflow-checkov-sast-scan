from __future__ import annotations

from typing import Any

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class S3PCIPrivateACL(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure PCI Scope buckets has private ACL (enable public ACL for non-pci buckets)"
        id = "CKV_CCL_CUSTOM_001"
        supported_resources = ("aws_s3_bucket",)
        # CheckCategories are defined in models/enums.py
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
            if tags.get("Scope") == "PCI":
                acl_block = conf['acl']
                if acl_block in [["public-read"], ["public-read-write"], ["website"]]:
                    return CheckResult.FAILED
        return CheckResult.PASSED


check = S3PCIPrivateACL()
