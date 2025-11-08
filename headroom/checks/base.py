"""
Base check framework for compliance checks.

This module provides an abstract base class that implements the Template Method
pattern for all compliance checks (SCP, RCP, etc.). Concrete checks only need to
implement three methods: analyze(), categorize_result(), and build_summary_fields().
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Generic, List, TypeVar

import boto3

from ..write_results import write_check_results
from ..output import OutputHandler

T = TypeVar('T')


@dataclass
class CategorizedCheckResult:
    """
    Categorized results from a compliance check.

    Contains violations, exemptions, and compliant resources after
    processing raw analysis results.
    """
    violations: List[Dict[str, Any]]
    exemptions: List[Dict[str, Any]]
    compliant: List[Dict[str, Any]]
    summary: Dict[str, Any]


class BaseCheck(ABC, Generic[T]):
    """
    Abstract base class for all compliance checks.

    Implements template method pattern for check execution.
    Subclasses only need to implement 3 methods:
    - analyze(): Perform AWS API calls
    - categorize_result(): Categorize a single result
    - build_summary_fields(): Build check-specific summary fields
    """

    # These are set by the @register_check decorator
    CHECK_NAME: str
    CHECK_TYPE: str

    def __init__(
        self,
        check_name: str,
        account_name: str,
        account_id: str,
        results_dir: str,
        exclude_account_ids: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the check.

        Args:
            check_name: Name of the check
            account_name: Account name
            account_id: Account ID
            results_dir: Base directory for results
            exclude_account_ids: If True, exclude account ID from results
            **kwargs: Additional check-specific parameters (ignored by base class)
        """
        self.check_name = check_name
        self.account_name = account_name
        self.account_id = account_id
        self.results_dir = results_dir
        self.exclude_account_ids = exclude_account_ids

    @abstractmethod
    def analyze(self, session: boto3.Session) -> List[T]:
        """
        Perform AWS API analysis.

        Args:
            session: boto3 Session with appropriate permissions

        Returns:
            List of raw analysis results
        """

    @abstractmethod
    def categorize_result(self, result: T) -> tuple[str, Dict[str, Any]]:
        """
        Categorize a single result.

        Args:
            result: Single analysis result

        Returns:
            Tuple of (category, result_dict) where category is one of:
            - "violation"
            - "exemption"
            - "compliant"
        """

    @abstractmethod
    def build_summary_fields(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """
        Build check-specific summary fields.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with check-specific summary fields
        """

    def _build_results_data(self, check_result: CategorizedCheckResult) -> Dict[str, Any]:
        """
        Build results data dictionary.

        Can be overridden by subclasses that need different result structures.

        Args:
            check_result: Categorized check result

        Returns:
            Dictionary with results data for JSON output
        """
        return {
            "summary": check_result.summary,
            "violations": check_result.violations,
            "exemptions": check_result.exemptions,
            "compliant_instances": check_result.compliant,
        }

    def execute(self, session: boto3.Session) -> None:
        """
        Execute the check (template method).

        This method orchestrates the entire check execution flow:
        1. Analyze: Call AWS APIs to gather data
        2. Categorize: Process each result into violations/exemptions/compliant
        3. Summarize: Build summary with check-specific fields
        4. Write: Save results to JSON file
        5. Log: Print completion message

        Args:
            session: boto3 Session with appropriate permissions
        """
        raw_results = self.analyze(session)

        violations = []
        exemptions = []
        compliant = []

        for result in raw_results:
            category, result_dict = self.categorize_result(result)
            if category == "violation":
                violations.append(result_dict)
            elif category == "exemption":
                exemptions.append(result_dict)
            elif category == "compliant":
                compliant.append(result_dict)

        check_result = CategorizedCheckResult(
            violations=violations,
            exemptions=exemptions,
            compliant=compliant,
            summary={},
        )

        summary = {
            "account_name": self.account_name,
            "account_id": self.account_id,
            "check": self.check_name,
            **self.build_summary_fields(check_result),
        }
        check_result.summary = summary

        results_data = self._build_results_data(check_result)

        write_check_results(
            check_name=self.check_name,
            account_name=self.account_name,
            account_id=self.account_id,
            results_data=results_data,
            results_base_dir=self.results_dir,
            exclude_account_ids=self.exclude_account_ids,
        )

        account_identifier = f"{self.account_name}_{self.account_id}"
        OutputHandler.check_completed(
            self.check_name,
            account_identifier,
            {
                "violations": len(violations),
                "exemptions": len(exemptions),
                "compliant": len(compliant),
            }
        )
