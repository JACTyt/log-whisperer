"""pySigma backend that compiles Sigma detections into DuckDB SQL boolean expressions.

Fields are read from the `fields` JSON column by their native names; matching is
case-insensitive (ILIKE) unless the rule uses `|cased`.
"""

import re
from typing import ClassVar

from sigma.conditions import ConditionAND, ConditionItem, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.types import CompareOperators, SigmaRegularExpressionFlag, SigmaString, SpecialChars


def sql_literal(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


class DuckDBBackend(TextQueryBackend):
    name: ClassVar[str] = "DuckDB SQL"
    formats: ClassVar[dict[str, str]] = {"default": "DuckDB WHERE expression"}
    requires_pipeline: ClassVar[bool] = False

    precedence: ClassVar[tuple[type[ConditionItem], type[ConditionItem], type[ConditionItem]]] = (
        ConditionNOT, ConditionAND, ConditionOR,
    )
    group_expression: ClassVar[str] = "({expr})"
    parenthesize: bool = True

    or_token: ClassVar[str] = "OR"
    and_token: ClassVar[str] = "AND"
    not_token: ClassVar[str] = "NOT"
    eq_token: ClassVar[str] = " = "

    eq_expression: ClassVar[str] = "{field} ILIKE {value} ESCAPE '\\'"
    wildcard_match_expression: ClassVar[str] = "{field} ILIKE {value} ESCAPE '\\'"
    case_sensitive_match_expression: ClassVar[str] = "{field} LIKE {value} ESCAPE '\\'"

    re_expression: ClassVar[str] = "regexp_matches({field}, '{regex}', 'c{flag_i}{flag_m}{flag_s}')"
    re_escape_char: ClassVar[str] = "'"
    re_escape: ClassVar[list[str]] = ["'"]
    re_escape_escape_char: bool = False
    re_flag_prefix: bool = False
    re_flags: dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE: "n",
        SigmaRegularExpressionFlag.DOTALL: "s",
    }

    compare_op_expression: ClassVar[str] = "TRY_CAST({field} AS DOUBLE) {operator} {value}"
    compare_operators: ClassVar[dict[CompareOperators, str]] = {
        CompareOperators.LT: "<", CompareOperators.LTE: "<=",
        CompareOperators.GT: ">", CompareOperators.GTE: ">=",
    }

    field_null_expression: ClassVar[str] = "{field} IS NULL"
    field_exists_expression: ClassVar[str] = "{field} IS NOT NULL"
    field_not_exists_expression: ClassVar[str] = "{field} IS NULL"

    unbound_value_str_expression: ClassVar[str] = "raw ILIKE ('%' || {value} || '%') ESCAPE '\\'"
    unbound_value_num_expression: ClassVar[str] = "contains(raw, '{value}')"
    unbound_value_re_expression: ClassVar[str] = "regexp_matches(raw, '{value}', 'c{flag_i}{flag_m}{flag_s}')"

    def escape_and_quote_field(self, field_name: str) -> str:
        path = '$."' + field_name.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return f"json_extract_string(fields, {sql_literal(path)})"

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """SigmaString -> quoted ILIKE pattern; literal %, _ and \\ are escaped with \\."""
        out = []
        for part in s.s:
            if isinstance(part, str):
                out.append(re.sub(r"([%_\\])", r"\\\1", part))
            elif part == SpecialChars.WILDCARD_MULTI:
                out.append("%")
            elif part == SpecialChars.WILDCARD_SINGLE:
                out.append("_")
            else:
                raise NotImplementedError(f"unsupported special value {part!r}")
        return sql_literal("".join(out))

    def convert_condition_field_eq_val_num(self, cond, state):
        return f"{self.escape_and_quote_field(cond.field)} = {sql_literal(str(cond.value))}"

    def convert_condition_field_eq_val_bool(self, cond, state):
        value = "true" if cond.value.boolean else "false"
        return f"lower({self.escape_and_quote_field(cond.field)}) = '{value}'"

    def convert_condition_val_num(self, cond, state):
        return self.unbound_value_num_expression.format(value=str(cond.value).replace("'", "''"))


def compile_rule(rule: SigmaRule) -> str:
    """Return one SQL boolean expression for the rule's detection (ORs multiple queries)."""
    queries = DuckDBBackend().convert_rule(rule)
    if not queries:
        raise NotImplementedError("rule produced no query")
    return queries[0] if len(queries) == 1 else " OR ".join(f"({q})" for q in queries)
