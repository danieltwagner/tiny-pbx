"""Test the interop runners without starting Docker, a PBX, phones, or SIPp."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import docker_interop
import interop


# Both PBXs of the fake environment keep running, unless a test says otherwise.
RUNNING = {"return_value.pbx.died.return_value": None, "return_value.g.pbx.died.return_value": None}


@patch.object(interop, "GROUP_TESTS", [])
@patch.object(interop, "TESTS", [("register", lambda env: "ok")])
@patch.object(interop, "Env", **RUNNING)
class RunnerTests(unittest.TestCase):
    def test_pass(self, factory):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(interop.main(["--only", "regist"]), 0)
        self.assertIn("1 passed", out.getvalue())
        factory.return_value.close.assert_called_once()

    def test_worker_exception_after_last_result(self, factory):
        factory.return_value.uas.values.side_effect = RuntimeError("worker crashed")
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            self.assertEqual(interop.main([]), 1)
        self.assertIn("worker crashed", out.getvalue())
        factory.return_value.close.assert_called_once()

    def test_pbx_that_exits_by_itself_fails_the_run(self, factory):
        factory.return_value.pbx.died.return_value = 0  # however it exited; no test noticed
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(interop.main([]), 1)
        self.assertIn("1 passed", out.getvalue())
        self.assertIn("exited by itself", out.getvalue())

    def test_missing_result(self, factory):
        with patch.object(interop, "run_block"), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(interop.main([]), 1)
        self.assertIn("tests not run: register", out.getvalue())

    def test_partial_match_is_an_error_before_setup(self, factory):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
            interop.main(["--only", "register,typo"])
        self.assertNotEqual(e.exception.code, 0)
        factory.assert_not_called()


class DockerRunnerTests(unittest.TestCase):
    # A filter that wrongly gets through must fail here, not go on to real Docker.
    @patch.object(docker_interop, "ensure_image", side_effect=AssertionError("reached Docker setup"))
    def test_bad_filter_is_an_error_before_docker_setup(self, ensure_image):
        for term in ("typo", "register,typo", "", "register,"):
            with self.subTest(term=term), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as e:
                    docker_interop.main(["--only", term])
                self.assertEqual(e.exception.code, 2)
        ensure_image.assert_not_called()


if __name__ == "__main__":
    unittest.main()
