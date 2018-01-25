#! /usr/bin/python
from mac_wrapper import * 
import unittest

class SelfTest(unittest.TestCase):
    def test_cmd(self):
        """
        test found is return false for friendly addr
        test missing is returning true for non-friendly addr
        :return:
        """
        # valid
        status = mac_not_in_db("c8:cb:b8:0d:28:33", "c8:cb:b8:0d:28:34")
        self.assertEquals(status, False, "should be in database in hw_addr")

    def test_cmd_same(self):
        """
        test found is return false for friendly addr
        test missing is returning true for non-friendly addr
        :return:
        """
        # same one
        status = mac_not_in_db("c8:cb:b8:0d:28:33", "c8:cb:b8:0d:28:33")
        self.assertEquals(status, False, "should be in database in hw_addr")

    def test_cmd_zeros(self):
        """
        test found is return false for friendly addr
        test missing is returning true for non-friendly addr
        :return:
        """
        # is missing
        status = mac_not_in_db("00:00:00:00:00:00", "00:00:00:00:00:00")
        self.assertEquals(status, True, "should be flagged as suspiciously true")

    def test_invalids_arg1(self):
        """
        test found is return false for friendly addr
        test missing is returning true for non-friendly addr
        :return:
        """
        status = mac_not_in_db(" ", "00:00:00:00:00:00")
        self.assertEquals(status, True, "should be flagged as True")

    def test_invalids_arg2(self):
        """
        test found is return false for friendly addr
        test missing is returning true for non-friendly addr
        :return:
        """
        status = mac_not_in_db("00:00:00:00:00:00", " ")
        self.assertEquals(status, True, "should be flagged as True")

if __name__ == 'main':
    unittest.main(verbosity=2)
