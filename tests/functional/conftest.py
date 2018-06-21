"""
Fixtures for pycryptoki functional tests
"""
import logging
import os
import sys

import pytest

from pycryptoki.defaults import ADMINISTRATOR_PASSWORD, ADMIN_PARTITION_LABEL, CO_PASSWORD
from pycryptoki.defines import CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK,  \
    CKF_PROTECTED_AUTHENTICATION_PATH
from pycryptoki.session_management import c_initialize, c_close_all_sessions, \
        c_open_session, login, c_finalize, \
    c_close_session, c_logout, c_get_token_info, get_firmware_version
from pycryptoki.token_management import c_init_token, c_get_mechanism_list
from . import config as test_config

LOG = logging.getLogger(__name__)


def pytest_addoption(parser):
    """
    Set up some commandline options so we can specify what we want to test.
    """
    optiongroup = parser.getgroup("pycryptoki", "Pycryptoki test options")

    optiongroup.addoption("--slot",
                          help="Specify the slot you are testing on (Can be Admin or "
                               "User slot)",
                          type=int,
                          default=os.environ.get("SLOT", 0),
                          dest="test_slot")
    optiongroup.addoption("--password",
                          help="Password for the Admin Slot. Can be None for PED-authentication "
                               "devices.",
                          action="store",
                          type=str,
                          default=ADMINISTRATOR_PASSWORD)
    optiongroup.addoption("--copassword",
                          help="Password for the Crypto Officer user/slot. Can be None for "
                               "PED-authentication.",
                          action="store",
                          type=str)
    optiongroup.addoption("--user",
                          help="User type to test with. Defaults to SO. Can also test w/ "
                               "Crypto Officer",
                          choices=["SO", "CO"],
                          default="SO",
                          action="store")
    optiongroup.addoption("--loglevel",
                          help="Specify what level of logging to run the tests ",
                          choices=["debug", "info", "warning", "error"],
                          default="warning")


def pytest_configure(config):
    """
    Set up the globals for this test run.
    """
    if config.getoption("loglevel", None):
        logger = logging.getLogger()
        log_formatter = logging.Formatter('%(asctime)s:%(name)s:%(levelname)s: %(message)s')
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(log_formatter)
        logger.addHandler(console_handler)
        logger.setLevel(config.getoption("loglevel").upper())

    test_config["test_slot"] = config.getoption("test_slot")
    test_config["user"] = config.getoption("user")
    c_initialize()
    try:
        # Factory Reset
        slot = test_config["test_slot"]
        ret, token_info = c_get_token_info(slot)
        flags = token_info['flags']
        is_ped = (flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0
        test_config["is_ped"] = is_ped
        test_config['firmware'] = get_firmware_version(slot)
        if is_ped:
            admin_pwd = None
            co_pwd = config.getoption("copassword", default=None)
        else:
            co_pwd = config.getoption("copassword", default=CO_PASSWORD)
            admin_pwd = config.getoption("password")

        if admin_pwd:
            admin_pwd = admin_pwd
        if co_pwd:
            co_pwd = co_pwd

        test_config['admin_pwd'] = admin_pwd
        test_config['co_pwd'] = co_pwd

        if config.getoption("user") == "CO":
            test_config['password'] = co_pwd
        else:
            test_config['password'] = admin_pwd
    finally:
        c_finalize()

@pytest.yield_fixture(scope='session', autouse=True)
def initialize(pytestconfig):
    """
    Initialize the library.
    """
    ret = c_initialize()
    assert ret == CKR_OK
    yield
    c_finalize()

@pytest.yield_fixture(scope="class")
def session(pytestconfig, initialize):
    """
    Creates & returns a session on the Admin slot.
    """
    _ = initialize
    session_flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION)

    slot = test_config["test_slot"]
    ret, h_session = c_open_session(slot, session_flags)
    assert ret == CKR_OK
    yield h_session
    c_close_session(slot)


@pytest.yield_fixture(scope="class")
def auth_session(pytestconfig, session):
    """
    Logs into the created admin session
    """
    slot = test_config["test_slot"]
    usertype = 0 if pytestconfig.getoption("user") == "SO" else 1
    login(session, slot, test_config["password"], usertype)
    yield session
    c_logout(session)


@pytest.yield_fixture(scope="class")
def valid_mechanisms():
    """
    Fixture that will query the active slot to get a list of valid mechanisms.
    This can be used for assertions across FW versions/configurations. Note, this ends up being
    just a list of constants, but it should match up w/ what you're using from `pycryptoki.defines`.

    :return: list of integers, each corresponding to a mechanism.
    """
    ret, raw_mechs = c_get_mechanism_list(slot=test_config['test_slot'])
    assert ret == CKR_OK
    yield raw_mechs
