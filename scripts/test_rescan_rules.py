#!/usr/bin/env python3
"""Unit tests for the stub SQL behaviour check.

The snippets live only in this file. They are not written into the agent workspace.

The `{call ?}` and rewritten SELECT cases are rebuilt from the phase 6 log.
The fix branches were reset after those runs, so the diffs are not in git.

The three header-flow fixes are rebuilt in this file from the saved run diffs.
They are not copied into the agent workspace.
"""
from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_app():
    fastapi = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class FastAPI:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def get(self, *args, **kwargs):
            return lambda fn: fn

        def post(self, *args, **kwargs):
            return lambda fn: fn

        def middleware(self, *args, **kwargs):
            return lambda fn: fn

    fastapi.FastAPI = FastAPI
    fastapi.HTTPException = HTTPException
    responses = types.ModuleType("fastapi.responses")
    responses.JSONResponse = dict
    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.responses"] = responses
    spec = importlib.util.spec_from_file_location(
        "stub_findings_app", ROOT / "lab" / "stub-findings-mcp" / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


app = _load_app()

# Original vulnerable method body. A prepared statement is used, but the
# password is still concatenated from the request parameter.
ORIGINAL = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = request.getParameter("BenchmarkTest00024");
    if (param == null) param = "";
    String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + param + "'";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.PreparedStatement statement =
                connection.prepareStatement(sql);
        statement.setString(1, "foo");
        statement.execute();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

# Last-run failure: the request input was removed and the password literal stayed.
INPUT_DELETED = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='***'";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.PreparedStatement statement =
                connection.prepareStatement(sql);
        statement.setString(1, "foo");
        statement.execute();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

# Last-run failure: the input variable remains, but the password is a new literal.
PASSWORD_HARDCODED = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = request.getParameter("BenchmarkTest00024");
    if (param == null) param = "";
    String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='***'";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.PreparedStatement statement =
                connection.prepareStatement(sql);
        statement.setString(1, "foo");
        statement.execute();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

# Correct shape, written for this test only. Both former values use placeholders
# and the request input is bound with setString.
CORRECT = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = request.getParameter("BenchmarkTest00024");
    if (param == null) param = "";
    String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=?";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.PreparedStatement statement =
                connection.prepareStatement(sql);
        statement.setString(1, "foo");
        statement.setString(2, param);
        statement.execute();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""


class SqliBehaviourTests(unittest.TestCase):
    def test_original_still_present(self) -> None:
        result = app.sqli_behaviour_checks(ORIGINAL, original=ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertFalse(result["checks"]["no_tainted_concat"])
        self.assertTrue(result["stub"])

    def test_input_deleted_still_present(self) -> None:
        result = app.sqli_behaviour_checks(INPUT_DELETED, original=ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertFalse(result["checks"]["tainted_input_bound"])
        self.assertFalse(result["checks"]["no_hardcoded_replacement"])

    def test_password_hardcoded_still_present(self) -> None:
        result = app.sqli_behaviour_checks(PASSWORD_HARDCODED, original=ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertFalse(result["checks"]["tainted_input_bound"])
        self.assertFalse(result["checks"]["no_hardcoded_replacement"])

    def test_parameterized_fix_cleared(self) -> None:
        result = app.sqli_behaviour_checks(CORRECT, original=ORIGINAL)
        self.assertFalse(result["still_present"])
        self.assertTrue(all(result["checks"].values()))
        self.assertTrue(result["stub"])


# Callable procedure-name case, rebuilt from the phase 6 log of the code-fix runs.
CALL_ORIGINAL = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = "";
    if (request.getHeader("BenchmarkTest00008") != null) {
        param = request.getHeader("BenchmarkTest00008");
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");
    String sql = "{call " + param + "}";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        java.sql.ResultSet rs = statement.executeQuery();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

CALL_PLACEHOLDER = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = "";
    if (request.getHeader("BenchmarkTest00008") != null) {
        param = request.getHeader("BenchmarkTest00008");
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");
    String sql = "{call ?}";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        statement.setString(1, param);
        java.sql.ResultSet rs = statement.executeQuery();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

CALL_REWRITTEN_SELECT = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = "";
    if (request.getHeader("BenchmarkTest00008") != null) {
        param = request.getHeader("BenchmarkTest00008");
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");
    String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='***'";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.PreparedStatement statement = connection.prepareStatement(sql);
        statement.setString(1, param);
        java.sql.ResultSet rs = statement.executeQuery();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

# A value argument can be a placeholder. The procedure name stays fixed.
CALL_CORRECT = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = request.getParameter("user");
    if (param == null) param = "";
    String sql = "{call authenticate(?)}";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        statement.setString(1, param);
        java.sql.ResultSet rs = statement.executeQuery();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""

CALL_CORRECT_ORIGINAL = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = request.getParameter("user");
    if (param == null) param = "";
    String sql = "{call authenticate('" + param + "')}";
    try {
        java.sql.Connection connection =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
        java.sql.CallableStatement statement = connection.prepareCall(sql);
        java.sql.ResultSet rs = statement.executeQuery();
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""


class BrokenFixTests(unittest.TestCase):
    def test_callable_original_still_present(self) -> None:
        result = app.sqli_behaviour_checks(CALL_ORIGINAL, original=CALL_ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertFalse(result["checks"]["no_tainted_concat"])

    def test_procedure_name_placeholder_still_present(self) -> None:
        result = app.sqli_behaviour_checks(CALL_PLACEHOLDER, original=CALL_ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertFalse(result["checks"]["no_identifier_placeholders"])

    def test_rewritten_select_still_present(self) -> None:
        result = app.sqli_behaviour_checks(CALL_REWRITTEN_SELECT, original=CALL_ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertFalse(result["checks"]["sql_text_preserved"])
        self.assertFalse(result["checks"]["call_type_kept"])

    def test_correct_callable_cleared(self) -> None:
        result = app.sqli_behaviour_checks(CALL_CORRECT, original=CALL_CORRECT_ORIGINAL)
        self.assertFalse(result["still_present"])
        self.assertTrue(all(result["checks"].values()))

    def test_correct_prepared_cleared(self) -> None:
        result = app.sqli_behaviour_checks(CORRECT, original=ORIGINAL)
        self.assertFalse(result["still_present"])
        self.assertTrue(all(result["checks"].values()))

    def test_statement_to_prepared_cleared(self) -> None:
        original = """
        public void doPost(HttpServletRequest request, HttpServletResponse response) {
            String param = request.getHeader("user");
            String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
            java.sql.Statement statement =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
            statement.executeUpdate(sql);
        }
        """
        fixed = """
        public void doPost(HttpServletRequest request, HttpServletResponse response) {
            String param = request.getHeader("user");
            String sql = "INSERT INTO users (username, password) VALUES ('foo',?)";
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.PreparedStatement statement = connection.prepareStatement(sql);
            statement.setString(1, param);
            statement.executeUpdate();
        }
        """
        result = app.sqli_behaviour_checks(fixed, original=original)
        self.assertFalse(result["still_present"])
        self.assertTrue(all(result["checks"].values()))


# Header enumeration flow. Rebuilt from the saved code-fix diffs: the value is
# taken with nextElement(), decoded, then bound. The three SQL strings differ
# only by the space before the placeholder, matching those diffs.
HEADER_ORIGINAL = """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    response.setContentType("text/html;charset=UTF-8");
    String param = "";
    java.util.Enumeration<String> headers = request.getHeaders("id");
    if (headers != null && headers.hasMoreElements()) {
        param = headers.nextElement();
    }
    param = java.net.URLDecoder.decode(param, "UTF-8");
    String sql = "INSERT INTO users (username, password) VALUES ('foo','" + param + "')";
    try {
        java.sql.Statement statement =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        int count = statement.executeUpdate(sql);
    } catch (java.sql.SQLException e) {
        throw new ServletException(e);
    }
}
"""


def _header_fix(sql: str, body: str) -> str:
    return HEADER_ORIGINAL.replace(
        'String sql = "INSERT INTO users (username, password) VALUES (\'foo\',\'" + param + "\')";\n'
        "    try {\n"
        "        java.sql.Statement statement =\n"
        "                org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();\n"
        "        int count = statement.executeUpdate(sql);",
        f'String sql = "{sql}";\n    try {{\n        {body}',
    )


HEADER_FIX_SPACE = _header_fix(
    "INSERT INTO users (username, password) VALUES ('foo', ?)",
    "java.sql.Connection c =\n"
    "                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();\n"
    "        java.sql.PreparedStatement statement = c.prepareStatement(sql);\n"
    "        statement.setString(1, param);\n"
    "        int count = statement.executeUpdate();",
)
HEADER_FIX_NAMED = _header_fix(
    "INSERT INTO users (username, password) VALUES ('foo', ?)",
    "java.sql.Connection conn =\n"
    "                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();\n"
    "        java.sql.PreparedStatement pstmt = conn.prepareStatement(sql);\n"
    "        pstmt.setString(1, param);\n"
    "        int count = pstmt.executeUpdate();",
)
HEADER_FIX_TIGHT = _header_fix(
    "INSERT INTO users (username, password) VALUES ('foo',?)",
    "java.sql.PreparedStatement statement =\n"
    "                org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection().prepareStatement(sql);\n"
    "        statement.setString(1, param);\n"
    "        int count = statement.executeUpdate();",
)


class HeaderFlowTests(unittest.TestCase):
    def test_header_original_still_present(self) -> None:
        result = app.sqli_behaviour_checks(HEADER_ORIGINAL, original=HEADER_ORIGINAL)
        self.assertTrue(result["still_present"])
        self.assertIn("param", result["tainted"])
        self.assertFalse(result["checks"]["no_tainted_concat"])

    def test_saved_fix_with_space_cleared(self) -> None:
        result = app.sqli_behaviour_checks(HEADER_FIX_SPACE, original=HEADER_ORIGINAL)
        self.assertFalse(result["still_present"], result["checks"])

    def test_saved_fix_named_statement_cleared(self) -> None:
        result = app.sqli_behaviour_checks(HEADER_FIX_NAMED, original=HEADER_ORIGINAL)
        self.assertFalse(result["still_present"], result["checks"])

    def test_saved_fix_without_space_cleared(self) -> None:
        result = app.sqli_behaviour_checks(HEADER_FIX_TIGHT, original=HEADER_ORIGINAL)
        self.assertFalse(result["still_present"], result["checks"])


if __name__ == "__main__":
    unittest.main()
